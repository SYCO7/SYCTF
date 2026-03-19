"""Plugin marketplace manager for SYCTF external module packs."""

from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.table import Table

from syctf.core.execution import safe_subprocess
from syctf.core.paths import get_plugins_dir
from syctf import __version__ as SYCTF_VERSION

_PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9._/-]{1,120}$")
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


class PluginManager:
    """Manage installation, listing, removal, and discovery of plugin packs."""

    def __init__(
        self,
        plugins_dir: Path | None = None,
        marketplace_template: str = "https://github.com/{plugin_name}/archive/refs/heads/main.zip",
    ) -> None:
        self.plugins_dir = plugins_dir or get_plugins_dir()
        self.marketplace_template = marketplace_template
        self.plugins_dir.mkdir(parents=True, exist_ok=True)

    def plugin_dir(self, plugin_name: str) -> Path:
        """Return canonical plugin directory path."""

        candidate = plugin_name.strip()
        if not candidate or not _PLUGIN_ID_RE.fullmatch(candidate):
            raise ValueError("Invalid plugin name")

        # Allow marketplace identifiers such as owner/repo while keeping local dir safe.
        local_name = candidate.replace("/", "_")
        target = (self.plugins_dir / local_name).resolve()
        if self.plugins_dir not in target.parents and target != self.plugins_dir:
            raise ValueError("Invalid plugin path")
        return target

    def _iter_plugin_dirs(self) -> list[Path]:
        """Return installed plugin directories under ~/.syctf/plugins/."""

        out: list[Path] = []
        for entry in sorted(self.plugins_dir.iterdir()):
            if not entry.is_dir():
                continue
            resolved = entry.resolve()
            if self.plugins_dir not in resolved.parents and resolved != self.plugins_dir:
                continue
            out.append(resolved)
        return out

    def _plugin_manifest(self, directory: Path) -> dict[str, Any] | None:
        """Load and validate manifest for one plugin directory."""

        manifest_path = directory / "plugin.json"
        if not manifest_path.exists() or not manifest_path.is_file():
            return None
        try:
            manifest = self._load_manifest(manifest_path)
            self._validate_manifest(manifest)
        except Exception:  # noqa: BLE001
            return None
        manifest["path"] = str(directory)
        manifest["dir_name"] = directory.name
        return manifest

    def _resolve_installed_plugin_dir(self, plugin_name: str) -> Path | None:
        """Resolve plugin directory by local dir name or manifest name."""

        requested = plugin_name.strip()
        if not requested:
            return None

        direct = self.plugin_dir(requested)
        if direct.exists() and direct.is_dir():
            return direct

        lowered = requested.lower()
        for directory in self._iter_plugin_dirs():
            manifest = self._plugin_manifest(directory)
            if not manifest:
                continue
            name = str(manifest.get("name", "")).strip().lower()
            if name == lowered or directory.name.lower() == lowered:
                return directory
        return None

    def list_plugins(self) -> list[dict[str, Any]]:
        """List installed plugins from manifest files."""

        items: list[dict[str, Any]] = []
        for entry in self._iter_plugin_dirs():
            payload = self._plugin_manifest(entry)
            if payload:
                items.append(payload)
        return items

    def get_plugin_info(self, plugin_name: str) -> dict[str, Any] | None:
        """Return manifest and compatibility metadata for one plugin."""

        directory = self._resolve_installed_plugin_dir(plugin_name)
        if directory is None:
            return None

        payload = self._plugin_manifest(directory)
        if payload is None:
            return None

        required = str(
            payload.get("requires_syctf_version", payload.get("min_syctf_version", ""))
        ).strip()
        payload["compatibility"] = self._compatibility_status(required)
        payload["current_syctf_version"] = SYCTF_VERSION
        return payload

    def remove_plugin(self, plugin_name: str) -> bool:
        """Remove installed plugin directory by name."""

        target = self._resolve_installed_plugin_dir(plugin_name)
        if target is None or not target.exists() or target == self.plugins_dir:
            return False
        shutil.rmtree(target)
        return True

    def install_plugin(self, plugin_name: str, console: Console | None = None) -> dict[str, Any]:
        """Install plugin from marketplace zip URL into plugins directory."""

        local_console = console or Console()
        target = self.plugin_dir(plugin_name)
        if target.exists():
            raise ValueError(f"Plugin already installed: {plugin_name}")

        url = self.marketplace_template.format(plugin_name=plugin_name)
        with tempfile.TemporaryDirectory(prefix="syctf_plugin_") as temp_dir:
            temp_zip = Path(temp_dir) / f"{plugin_name}.zip"

            with local_console.status(f"[cyan]Downloading plugin {plugin_name}...[/cyan]", spinner="dots"):
                response = requests.get(url, timeout=30.0)
                response.raise_for_status()
                temp_zip.write_bytes(response.content)

            extract_root = Path(temp_dir) / "extract"
            extract_root.mkdir(parents=True, exist_ok=True)

            with local_console.status("[cyan]Extracting plugin archive...[/cyan]", spinner="dots"):
                self._safe_extract_zip(temp_zip, extract_root)

            source_dir = self._find_plugin_root(extract_root)
            manifest = self._load_manifest(source_dir / "plugin.json")

            self._validate_manifest(manifest)
            compatibility = self._compatibility_status(
                str(manifest.get("requires_syctf_version", manifest.get("min_syctf_version", ""))).strip()
            )
            modules_dir = source_dir / "modules"
            if not modules_dir.exists() or not modules_dir.is_dir():
                raise ValueError("Plugin package missing modules/ directory")

            target.mkdir(parents=True, exist_ok=False)
            shutil.copytree(source_dir, target, dirs_exist_ok=True)

            requirements_file = target / "requirements.txt"
            if requirements_file.exists():
                with local_console.status("[cyan]Installing plugin requirements...[/cyan]", spinner="dots"):
                    proc = safe_subprocess(
                        [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)],
                        timeout=600.0,
                    )
                if proc.returncode != 0:
                    self.remove_plugin(plugin_name)
                    error_text = proc.stderr.strip() or proc.stdout.strip() or "unknown pip error"
                    raise RuntimeError(f"Failed to install plugin dependencies: {error_text}")

        if compatibility["level"] == "warn":
            manifest["compatibility_warning"] = compatibility["message"]

        return manifest

    def compatibility_warnings(self) -> list[str]:
        """Return compatibility warnings for installed plugins."""

        warnings: list[str] = []
        for item in self.list_plugins():
            required = str(
                item.get("requires_syctf_version", item.get("min_syctf_version", ""))
            ).strip()
            status = self._compatibility_status(required)
            if status["level"] == "warn":
                name = str(item.get("name", item.get("dir_name", "plugin")))
                warnings.append(f"{name}: {status['message']}")
        return warnings

    @staticmethod
    def _parse_version(text: str) -> tuple[int, int, int] | None:
        """Parse semantic major.minor.patch from version string."""

        match = _VERSION_RE.match(text.strip())
        if not match:
            return None
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))

    @classmethod
    def _compatibility_status(cls, required: str) -> dict[str, str]:
        """Compare plugin required version against current SYCTF version."""

        if not required:
            return {"level": "ok", "message": "No minimum SYCTF version declared"}

        have = cls._parse_version(SYCTF_VERSION)
        need = cls._parse_version(required)
        if have is None or need is None:
            return {
                "level": "warn",
                "message": f"Unable to parse version requirement '{required}'",
            }

        if have < need:
            return {
                "level": "warn",
                "message": (
                    f"Requires SYCTF>={required} but current version is {SYCTF_VERSION}"
                ),
            }
        return {"level": "ok", "message": f"Compatible with SYCTF {SYCTF_VERSION}"}

    def discover_module_roots(self) -> list[Path]:
        """Discover plugin module roots for dynamic loading."""

        roots: list[Path] = []
        for plugin in self.list_plugins():
            plugin_name = str(plugin.get("name", "")).strip()
            if not plugin_name:
                continue
            root = self.plugin_dir(plugin_name)
            modules_dir = root / "modules"
            if modules_dir.exists() and modules_dir.is_dir():
                roots.append(modules_dir)
        return roots

    @staticmethod
    def _safe_extract_zip(zip_path: Path, destination: Path) -> None:
        """Extract zip archive while preventing path traversal."""

        destination = destination.resolve()
        with zipfile.ZipFile(zip_path, "r") as archive:
            for member in archive.infolist():
                member_path = (destination / member.filename).resolve()
                if destination not in member_path.parents and member_path != destination:
                    raise ValueError("Unsafe path traversal detected in plugin archive")
            archive.extractall(destination)

    @staticmethod
    def _find_plugin_root(extract_root: Path) -> Path:
        """Find extracted top-level plugin source directory."""

        children = [item for item in extract_root.iterdir() if item.is_dir()]
        if not children:
            raise ValueError("Plugin archive is empty")

        # GitHub zip archives typically unpack into one top-level directory.
        if len(children) == 1:
            return children[0]

        for child in children:
            if (child / "plugin.json").exists() and (child / "modules").exists():
                return child

        raise ValueError("Could not locate plugin root containing plugin.json and modules/")

    @staticmethod
    def _load_manifest(manifest_path: Path) -> dict[str, Any]:
        """Load plugin manifest from plugin.json."""

        if not manifest_path.exists():
            raise ValueError("plugin.json is missing from plugin package")
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid plugin.json format") from exc
        if not isinstance(payload, dict):
            raise ValueError("plugin.json must contain a JSON object")
        return payload

    @staticmethod
    def _validate_manifest(manifest: dict[str, Any]) -> None:
        """Validate plugin manifest schema fields."""

        required_fields = ["name", "version", "author", "modules"]
        for field in required_fields:
            if field not in manifest:
                raise ValueError(f"plugin.json missing required field: {field}")

        if not isinstance(manifest["name"], str) or not manifest["name"].strip():
            raise ValueError("plugin.json field 'name' must be a non-empty string")
        if not isinstance(manifest["version"], str) or not manifest["version"].strip():
            raise ValueError("plugin.json field 'version' must be a non-empty string")
        if not isinstance(manifest["author"], str) or not manifest["author"].strip():
            raise ValueError("plugin.json field 'author' must be a non-empty string")
        if not isinstance(manifest["modules"], list):
            raise ValueError("plugin.json field 'modules' must be a list")
        if not all(isinstance(item, str) and item.strip() for item in manifest["modules"]):
            raise ValueError("plugin.json field 'modules' must contain non-empty strings")

        optional_version = manifest.get("requires_syctf_version", manifest.get("min_syctf_version"))
        if optional_version is not None and not isinstance(optional_version, str):
            raise ValueError("plugin.json requires_syctf_version must be a string")

        plugin_name = str(manifest["name"]).strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", plugin_name):
            raise ValueError("plugin.json field 'name' contains unsupported characters")


def run_plugin_command(args, console: Console, logger) -> int:
    """Execute plugin marketplace command actions from argparse args."""

    manager = PluginManager()

    action = getattr(args, "plugin_action", "")
    if action == "install":
        plugin_name = str(args.plugin_name).strip()
        if not plugin_name:
            console.print("[bold red]Plugin name is required.[/bold red]")
            return 2
        try:
            manifest = manager.install_plugin(plugin_name, console=console)
        except Exception as exc:  # noqa: BLE001
            logger.exception("plugin install failed for %s: %s", plugin_name, exc)
            console.print(f"[bold red]Plugin install failed:[/bold red] {exc}")
            return 1
        console.print(
            f"[green]Installed plugin:[/green] {manifest.get('name')} "
            f"v{manifest.get('version')} by {manifest.get('author')}"
        )
        warning = str(manifest.get("compatibility_warning", "")).strip()
        if warning:
            console.print(f"[yellow]Compatibility warning:[/yellow] {warning}")
        return 0

    if action == "list":
        plugins = manager.list_plugins()
        if not plugins:
            console.print("[yellow]No plugins installed.[/yellow]")
            return 0

        table = Table(title="Installed Plugins")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Author", style="white")
        table.add_column("Modules", style="magenta")
        table.add_column("Compat", style="yellow")
        for item in plugins:
            modules = item.get("modules", [])
            module_str = ", ".join(modules) if isinstance(modules, list) else ""
            required = str(
                item.get("requires_syctf_version", item.get("min_syctf_version", ""))
            ).strip()
            compat = manager._compatibility_status(required)
            table.add_row(
                str(item.get("name", "")),
                str(item.get("version", "")),
                str(item.get("author", "")),
                module_str,
                compat["message"],
            )
        console.print(table)
        return 0

    if action == "info":
        plugin_name = str(args.plugin_name).strip()
        if not plugin_name:
            console.print("[bold red]Plugin name is required.[/bold red]")
            return 2

        info = manager.get_plugin_info(plugin_name)
        if not info:
            console.print(f"[yellow]Plugin not found:[/yellow] {plugin_name}")
            return 1

        modules = info.get("modules", [])
        module_str = ", ".join(modules) if isinstance(modules, list) else ""
        compat = info.get("compatibility", {"message": "unknown"})

        table = Table(title=f"Plugin Info: {info.get('name', plugin_name)}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Name", str(info.get("name", "")))
        table.add_row("Version", str(info.get("version", "")))
        table.add_row("Author", str(info.get("author", "")))
        table.add_row("Path", str(info.get("path", "")))
        table.add_row("Modules", module_str or "(none)")
        table.add_row("Requires SYCTF", str(info.get("requires_syctf_version", info.get("min_syctf_version", "(not set)"))))
        table.add_row("Compatibility", str(compat.get("message", "unknown")))
        console.print(table)
        return 0

    if action == "remove":
        plugin_name = str(args.plugin_name).strip()
        if not plugin_name:
            console.print("[bold red]Plugin name is required.[/bold red]")
            return 2
        removed = manager.remove_plugin(plugin_name)
        if not removed:
            console.print(f"[yellow]Plugin not found:[/yellow] {plugin_name}")
            return 1
        console.print(f"[green]Removed plugin:[/green] {plugin_name}")
        return 0

    console.print("[bold red]Unknown plugin action.[/bold red]")
    return 2

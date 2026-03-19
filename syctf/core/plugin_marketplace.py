"""Plugin marketplace manager for SYCTF external module packs."""

from __future__ import annotations

import ast
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from syctf.core.execution import safe_subprocess
from syctf.core.paths import get_plugins_dir
from syctf import __version__ as SYCTF_VERSION

_PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9._/-]{1,120}$")
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")
_GIT_URL_RE = re.compile(r"^(https?://|ssh://|git@|file://).+", re.IGNORECASE)
_MARKETPLACE_INDEX_URL = (
    "https://raw.githubusercontent.com/SYCO7/syctf-marketplace/main/index.json"
)


class PluginManager:
    """Manage installation, listing, removal, and discovery of plugin packs."""

    def __init__(
        self,
        plugins_dir: Path | None = None,
        marketplace_index_url: str = _MARKETPLACE_INDEX_URL,
    ) -> None:
        self.plugins_dir = plugins_dir or get_plugins_dir()
        self.marketplace_index_url = str(marketplace_index_url).strip() or _MARKETPLACE_INDEX_URL
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

    def install_plugin(self, source: str, console: Console | None = None) -> dict[str, Any]:
        """Install plugin from git URL or marketplace index name."""

        local_console = console or Console()
        source_token = str(source).strip()
        if not source_token:
            raise ValueError("Plugin source is required")

        plugin_label, git_url = self._resolve_install_source(source_token)

        with tempfile.TemporaryDirectory(prefix="syctf_plugin_") as temp_dir:
            clone_dir = Path(temp_dir) / "repo"
            with local_console.status(f"[cyan]Cloning plugin {plugin_label}...[/cyan]", spinner="dots"):
                self._git_clone(git_url, clone_dir)

            source_dir = self._find_plugin_root(clone_dir)
            manifest = self._load_manifest(source_dir / "plugin.json")
            self._validate_manifest(manifest)

            plugin_name = str(manifest.get("name", "")).strip()
            target = self.plugin_dir(plugin_name)
            if target.exists():
                raise ValueError(f"Plugin already installed: {plugin_name}")

            compatibility = self._compatibility_status(
                str(manifest.get("requires_syctf_version", manifest.get("min_syctf_version", ""))).strip()
            )

            self._validate_plugin_layout(source_dir, manifest)
            self._enforce_subprocess_policy(source_dir, manifest)

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

        manifest["installed_from"] = git_url
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
            entry = str(plugin.get("entry", "")).strip()
            if entry:
                roots.append(root)
                continue

            modules_dir = root / "modules"
            if modules_dir.exists() and modules_dir.is_dir():
                roots.append(modules_dir)
        return roots

    @staticmethod
    def _find_plugin_root(clone_root: Path) -> Path:
        """Find plugin root containing plugin.json in cloned repository."""

        if (clone_root / "plugin.json").exists():
            return clone_root

        for candidate in sorted(clone_root.rglob("plugin.json")):
            root = candidate.parent.resolve()
            if clone_root == root or clone_root in root.parents:
                return root

        raise ValueError("Could not locate plugin root containing plugin.json")

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

        if not isinstance(manifest.get("name"), str) or not str(manifest["name"]).strip():
            raise ValueError("plugin.json field 'name' must be a non-empty string")
        if not isinstance(manifest.get("version"), str) or not str(manifest["version"]).strip():
            raise ValueError("plugin.json field 'version' must be a non-empty string")

        has_entry = isinstance(manifest.get("entry"), str) and str(manifest.get("entry", "")).strip()
        has_legacy_modules = isinstance(manifest.get("modules"), list)
        if not has_entry and not has_legacy_modules:
            raise ValueError("plugin.json must include either 'entry' or 'modules'")

        if has_entry:
            entry = str(manifest.get("entry", "")).strip()
            if entry.startswith("/") or ".." in entry.replace("\\", "/"):
                raise ValueError("plugin.json field 'entry' must be a safe relative path")

        if has_legacy_modules:
            modules = manifest.get("modules", [])
            if not all(isinstance(item, str) and item.strip() for item in modules):
                raise ValueError("plugin.json field 'modules' must contain non-empty strings")

        if "allow_subprocess" in manifest and not isinstance(manifest.get("allow_subprocess"), bool):
            raise ValueError("plugin.json field 'allow_subprocess' must be boolean")

        if "author" in manifest and not isinstance(manifest.get("author"), str):
            raise ValueError("plugin.json field 'author' must be a string when provided")

        optional_version = manifest.get("requires_syctf_version", manifest.get("min_syctf_version"))
        if optional_version is not None and not isinstance(optional_version, str):
            raise ValueError("plugin.json requires_syctf_version must be a string")

        plugin_name = str(manifest["name"]).strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", plugin_name):
            raise ValueError("plugin.json field 'name' contains unsupported characters")

    def _resolve_install_source(self, source: str) -> tuple[str, str]:
        """Resolve a source token into marketplace name and git URL."""

        token = source.strip()
        if _GIT_URL_RE.match(token) or token.endswith(".git"):
            return (token, token)

        if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", token):
            index = self._load_marketplace_index()
            found = index.get(token.lower())
            if found:
                return (token, found)

        if re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", token):
            return (token, f"https://github.com/{token}.git")

        raise ValueError(f"Could not resolve plugin source: {token}")

    def _load_marketplace_index(self) -> dict[str, str]:
        """Load marketplace index map: plugin name -> git URL."""

        response = requests.get(self.marketplace_index_url, timeout=10.0)
        response.raise_for_status()
        payload = response.json()

        entries: list[dict[str, Any]] = []
        if isinstance(payload, dict):
            candidates = payload.get("plugins", payload.get("items", []))
            if isinstance(candidates, list):
                entries = [item for item in candidates if isinstance(item, dict)]
        elif isinstance(payload, list):
            entries = [item for item in payload if isinstance(item, dict)]

        mapping: dict[str, str] = {}
        for item in entries:
            name = str(item.get("name", "")).strip().lower()
            git_url = str(item.get("git_url") or item.get("url") or "").strip()
            repo = str(item.get("repo", "")).strip()

            if not git_url and re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", repo):
                git_url = f"https://github.com/{repo}.git"

            if not name or not git_url:
                continue
            mapping[name] = git_url
        return mapping

    @staticmethod
    def _git_clone(git_url: str, destination: Path) -> None:
        """Clone plugin source repository into temporary destination."""

        destination.parent.mkdir(parents=True, exist_ok=True)
        proc = safe_subprocess(
            ["git", "clone", "--depth", "1", git_url, str(destination)],
            timeout=120.0,
        )
        if proc.returncode != 0:
            error_text = proc.stderr.strip() or proc.stdout.strip() or "git clone failed"
            raise RuntimeError(f"Failed to clone plugin repository: {error_text}")

    def _validate_plugin_layout(self, source_dir: Path, manifest: dict[str, Any]) -> None:
        """Validate plugin package files for supported schema layouts."""

        entry = str(manifest.get("entry", "")).strip()
        if entry:
            entry_path = (source_dir / entry).resolve()
            if source_dir.resolve() not in entry_path.parents:
                raise ValueError("plugin entry path escapes plugin root")
            if not entry_path.exists() or not entry_path.is_file():
                raise ValueError(f"Plugin entry file not found: {entry}")
            if entry_path.suffix != ".py":
                raise ValueError("Plugin entry must be a Python file")
            return

        modules_dir = source_dir / "modules"
        if not modules_dir.exists() or not modules_dir.is_dir():
            raise ValueError("Plugin package missing modules/ directory")

    def _enforce_subprocess_policy(self, source_dir: Path, manifest: dict[str, Any]) -> None:
        """Block subprocess import usage unless explicitly allowed."""

        allow_subprocess = bool(manifest.get("allow_subprocess", False))
        if allow_subprocess:
            return

        py_files = list(source_dir.rglob("*.py"))
        for py_file in py_files:
            if py_file.name.startswith("__"):
                continue
            if self._uses_subprocess(py_file):
                raise ValueError(
                    "Plugin blocked by security policy: subprocess usage detected. "
                    "Set allow_subprocess=true in plugin.json to allow."
                )

    @staticmethod
    def _uses_subprocess(file_path: Path) -> bool:
        """Return True when a Python file imports subprocess."""

        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            return False

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(alias.name == "subprocess" for alias in node.names):
                    return True
            if isinstance(node, ast.ImportFrom):
                if node.module == "subprocess":
                    return True
        return False

    def diagnostics(self) -> dict[str, Any]:
        """Return summary diagnostics for installed plugin system."""

        plugins = self.list_plugins()
        insecure: list[str] = []
        invalid: list[str] = []

        for item in plugins:
            plugin_name = str(item.get("name", "")).strip()
            plugin_root = self.plugin_dir(plugin_name)
            try:
                self._validate_plugin_layout(plugin_root, item)
            except Exception:
                invalid.append(plugin_name)
                continue

            if bool(item.get("allow_subprocess", False)):
                insecure.append(plugin_name)

        return {
            "plugins_dir": str(self.plugins_dir),
            "plugin_count": len(plugins),
            "allow_subprocess_plugins": insecure,
            "invalid_plugins": invalid,
            "marketplace_index": self.marketplace_index_url,
        }


def run_plugin_command(args, console: Console, logger) -> int:
    """Execute plugin marketplace command actions from argparse args."""

    manager = PluginManager()

    action = getattr(args, "plugin_action", "")
    if action == "install":
        plugin_source = str(args.plugin_source).strip()
        if not plugin_source:
            console.print("[bold red]Plugin source is required.[/bold red]")
            return 2
        try:
            manifest = manager.install_plugin(plugin_source, console=console)
        except Exception as exc:  # noqa: BLE001
            logger.exception("plugin install failed for %s: %s", plugin_source, exc)
            console.print(f"[bold red]Plugin install failed:[/bold red] {exc}")
            return 1
        console.print(
            f"[green]Installed plugin:[/green] {manifest.get('name')} "
            f"v{manifest.get('version')}"
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
        table.add_column("Entry", style="white")
        table.add_column("Schema", style="magenta")
        table.add_column("Compat", style="yellow")
        for item in plugins:
            entry = str(item.get("entry", "")).strip() or "modules/*"
            schema = "entry" if str(item.get("entry", "")).strip() else "legacy"
            required = str(
                item.get("requires_syctf_version", item.get("min_syctf_version", ""))
            ).strip()
            compat = manager._compatibility_status(required)
            table.add_row(
                str(item.get("name", "")),
                str(item.get("version", "")),
                entry,
                schema,
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
        table.add_row("Path", str(info.get("path", "")))
        table.add_row("Entry", str(info.get("entry", "(legacy modules layout)")))
        table.add_row("Modules", module_str or "(none)")
        table.add_row("Requires SYCTF", str(info.get("requires_syctf_version", info.get("min_syctf_version", "(not set)"))))
        table.add_row("Compatibility", str(compat.get("message", "unknown")))
        table.add_row("Allow Subprocess", str(bool(info.get("allow_subprocess", False))))
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

    if action == "diagnostics":
        diag = manager.diagnostics()
        allow_sub = diag.get("allow_subprocess_plugins", [])
        invalid = diag.get("invalid_plugins", [])
        console.print(
            Panel(
                f"[green]Plugins dir:[/green] {diag.get('plugins_dir')}\n"
                f"[green]Installed plugins:[/green] {diag.get('plugin_count')}\n"
                f"[green]Marketplace index:[/green] {diag.get('marketplace_index')}\n"
                f"[yellow]allow_subprocess plugins:[/yellow] {allow_sub or 'none'}\n"
                f"[yellow]Invalid plugin layouts:[/yellow] {invalid or 'none'}",
                title="Plugin Diagnostics",
                border_style="cyan",
            )
        )
        return 0

    console.print("[bold red]Unknown plugin action.[/bold red]")
    return 2

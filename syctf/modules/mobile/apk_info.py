"""APK static overview: manifest, permissions, components, security flags."""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.utils.axml import AxmlError, parse_axml

_COMPONENTS = {"activity", "service", "receiver", "provider"}


class ApkInfoPlugin:
    """Parse AndroidManifest.xml and flag common misconfigurations."""

    name = "apk-info"
    description = "APK manifest, permissions, components, and security-flag review"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--file", required=True, help="Path to .apk")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        path = Path(args.file).expanduser()
        if not path.is_file() or not zipfile.is_zipfile(path):
            context.console.print("[bold red]Not a valid APK/zip file.[/bold red]")
            return 2

        context.logger.info("APK info file=%s", path)
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                manifest_bytes = zf.read("AndroidManifest.xml") if "AndroidManifest.xml" in names else b""
        except (KeyError, zipfile.BadZipFile) as exc:
            context.console.print(f"[bold red]APK read error:[/bold red] {exc}")
            return 1

        package = version_name = min_sdk = target_sdk = ""
        app_flags: dict[str, str] = {}
        permissions: list[str] = []
        components: list[tuple[str, str, str]] = []  # (type, name, exported)
        findings: list[str] = []

        if manifest_bytes:
            try:
                for el in parse_axml(manifest_bytes):
                    tag = el.tag.lower()
                    if tag == "manifest":
                        package = el.attrs.get("package", package)
                        version_name = el.attrs.get("versionName", version_name)
                    elif tag == "uses-sdk":
                        min_sdk = el.attrs.get("minSdkVersion", min_sdk)
                        target_sdk = el.attrs.get("targetSdkVersion", target_sdk)
                    elif tag == "uses-permission":
                        name = el.attrs.get("name", "")
                        if name:
                            permissions.append(name)
                    elif tag == "application":
                        for key in ("debuggable", "allowBackup", "usesCleartextTraffic"):
                            if key in el.attrs:
                                app_flags[key] = el.attrs[key]
                    elif tag in _COMPONENTS:
                        components.append((tag, el.attrs.get("name", "?"), el.attrs.get("exported", "")))
            except AxmlError as exc:
                context.console.print(f"[yellow]Manifest parse failed ({exc}); showing structure only.[/yellow]")
        else:
            context.console.print("[yellow]No AndroidManifest.xml found in APK.[/yellow]")

        # -- security findings --
        if app_flags.get("debuggable") == "true":
            findings.append("android:debuggable=true (app is debuggable in production)")
        if app_flags.get("allowBackup", "true") == "true":
            findings.append("android:allowBackup=true (adb backup can exfiltrate app data)")
        if app_flags.get("usesCleartextTraffic") == "true":
            findings.append("android:usesCleartextTraffic=true (HTTP allowed)")
        exported = [c for c in components if c[2] == "true"]
        if exported:
            findings.append(f"{len(exported)} exported component(s) — check for unprotected entry points")

        overview = Table(title=f"APK: {path.name}", show_header=False)
        overview.add_column("Field", style="cyan", no_wrap=True)
        overview.add_column("Value", style="white")
        overview.add_row("package", package or "(unknown)")
        overview.add_row("versionName", version_name or "(unknown)")
        overview.add_row("minSdk / targetSdk", f"{min_sdk or '?'} / {target_sdk or '?'}")
        overview.add_row("permissions", str(len(permissions)))
        overview.add_row("components", str(len(components)))
        overview.add_row("dex files", str(sum(1 for n in names if n.endswith(".dex"))))
        overview.add_row("native libs", str(sum(1 for n in names if n.endswith(".so"))))
        context.console.print(overview)

        if permissions:
            dangerous = [p for p in permissions if p.split(".")[-1] in {
                "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "RECORD_AUDIO",
                "ACCESS_FINE_LOCATION", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
                "CAMERA", "READ_CALL_LOG", "REQUEST_INSTALL_PACKAGES",
            }]
            perm_table = Table(title=f"Permissions ({len(permissions)}, {len(dangerous)} sensitive)")
            perm_table.add_column("Permission", style="green")
            perm_table.add_column("Sensitive", style="yellow")
            for perm in sorted(permissions):
                perm_table.add_row(perm, "⚠" if perm in dangerous else "")
            context.console.print(perm_table)

        if exported:
            exp_table = Table(title=f"Exported components ({len(exported)})")
            exp_table.add_column("Type", style="cyan")
            exp_table.add_column("Name", style="green")
            for ctype, cname, _ in exported:
                exp_table.add_row(ctype, cname)
            context.console.print(exp_table)

        if findings:
            context.console.print("[bold red]Security findings:[/bold red]")
            for finding in findings:
                context.console.print(f"  - {finding}")
        else:
            context.console.print("[green]No obvious manifest misconfigurations.[/green]")

        context.cache["apk_package"] = package
        return 0


plugin = ApkInfoPlugin()

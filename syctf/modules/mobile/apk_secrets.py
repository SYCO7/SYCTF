"""Scan an APK for hardcoded secrets and interesting URLs."""

from __future__ import annotations

import argparse
import re
import zipfile
from pathlib import Path

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.utils.secrets import scan_secrets

_TEXTY = (".xml", ".json", ".properties", ".txt", ".js", ".html", ".smali", ".kt", ".java", ".cfg", ".yml")
_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,120}")


class ApkSecretsPlugin:
    """Grep APK contents for API keys, tokens, private keys, and endpoints."""

    name = "apk-secrets"
    description = "Scan APK (resources, assets, dex) for hardcoded secrets and URLs"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--file", required=True, help="Path to .apk")
        parser.add_argument("--max-urls", type=int, default=60, help="Max URLs to display")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        path = Path(args.file).expanduser()
        if not path.is_file() or not zipfile.is_zipfile(path):
            context.console.print("[bold red]Not a valid APK/zip file.[/bold red]")
            return 2

        context.logger.info("APK secrets file=%s", path)
        secrets = []
        urls: set[str] = set()
        try:
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.file_size > 8_000_000:  # skip huge blobs
                        continue
                    name = info.filename
                    try:
                        blob = zf.read(name)
                    except (KeyError, zipfile.BadZipFile):
                        continue
                    for match in _URL_RE.findall(blob):
                        urls.add(match.decode("ascii", "ignore"))
                    if name.endswith(_TEXTY) or name.endswith(".dex") or name == "AndroidManifest.xml":
                        text = blob.decode("latin-1", "ignore")
                        secrets.extend(scan_secrets(text, source=name))
        except zipfile.BadZipFile as exc:
            context.console.print(f"[bold red]APK read error:[/bold red] {exc}")
            return 1

        # de-dup secrets across files by (kind, value)
        seen: set[tuple[str, str]] = set()
        unique = []
        for hit in secrets:
            key = (hit.kind, hit.value)
            if key not in seen:
                seen.add(key)
                unique.append(hit)

        if unique:
            table = Table(title=f"Secrets in {path.name} ({len(unique)})")
            table.add_column("Kind", style="red", no_wrap=True)
            table.add_column("Value", style="yellow")
            table.add_column("File", style="dim")
            for hit in unique:
                table.add_row(hit.kind, hit.value, hit.context)
            context.console.print(table)
        else:
            context.console.print("[green]No hardcoded secrets matched.[/green]")

        interesting = sorted(
            u for u in urls
            if not u.startswith(("http://schemas.android.com", "http://www.w3.org", "https://www.w3.org"))
        )[: max(1, int(args.max_urls))]
        if interesting:
            url_table = Table(title=f"URLs ({len(urls)} found, showing {len(interesting)})")
            url_table.add_column("URL", style="cyan")
            for url in interesting:
                url_table.add_row(url)
            context.console.print(url_table)

        context.cache["apk_secrets"] = [(h.kind, h.value) for h in unique]
        return 0


plugin = ApkSecretsPlugin()

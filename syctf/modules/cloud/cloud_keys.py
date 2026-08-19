"""Scan a file, directory, or text for cloud credentials and secrets."""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.utils.secrets import scan_secrets

_MAX_FILE = 5_000_000
_MAX_FILES = 500


class CloudKeysPlugin:
    """Grep provided content for AWS/GCP/Azure keys, tokens, and private keys."""

    name = "cloud-keys"
    description = "Find cloud credentials/secrets in a file, directory, or raw text"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--path", help="File or directory to scan")
        group.add_argument("--text", help="Raw text to scan")

    def _iter_texts(self, path: Path):
        if path.is_file():
            files = [path]
        else:
            files = [p for p in path.rglob("*") if p.is_file()][:_MAX_FILES]
        for file in files:
            try:
                if file.stat().st_size > _MAX_FILE:
                    continue
                yield file.name, file.read_text(encoding="latin-1", errors="ignore")
            except OSError:
                continue

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        hits = []
        if args.text:
            hits = scan_secrets(args.text, source="<text>")
        else:
            path = Path(args.path).expanduser()
            if not path.exists():
                context.console.print("[bold red]Path not found.[/bold red]")
                return 2
            context.logger.info("cloud cloud-keys path=%s", path)
            for name, text in self._iter_texts(path):
                hits.extend(scan_secrets(text, source=name))

        # de-dup
        seen: set[tuple[str, str]] = set()
        unique = []
        for hit in hits:
            key = (hit.kind, hit.value)
            if key not in seen:
                seen.add(key)
                unique.append(hit)

        if not unique:
            context.console.print("[green]No cloud credentials or secrets found.[/green]")
            return 0

        table = Table(title=f"Secrets found ({len(unique)})")
        table.add_column("Kind", style="red", no_wrap=True)
        table.add_column("Value", style="yellow")
        table.add_column("Source", style="dim")
        for hit in unique:
            table.add_row(hit.kind, hit.value, hit.context)
        context.console.print(table)
        context.cache["cloud_secrets"] = [(h.kind, h.value) for h in unique]
        return 0


plugin = CloudKeysPlugin()

"""Strings extraction helper for reverse engineering tasks."""

from __future__ import annotations

import argparse
import string
from pathlib import Path

from rich.panel import Panel
from rich.table import Table

from syctf.core.types import ExecutionContext

name = "strings-analyzer"
description = "Extract printable strings from files or raw text"

MAX_BYTES = 5_000_000


class StringsAnalyzerPlugin:
    """Extract printable strings and highlight suspicious entries."""

    name = name
    description = description

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register module arguments."""

        parser.add_argument("target", help="Target file path or raw text")
        parser.add_argument("--min-len", type=int, default=4, help="Minimum string length")
        parser.add_argument("--limit", type=int, default=50, help="Maximum output rows")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Run strings analysis and render rich output."""

        target = str(args.target).strip()
        if not target:
            raise ValueError("Target cannot be empty")

        min_len = max(2, int(args.min_len))
        limit = max(1, min(300, int(args.limit)))

        payload = _load_payload(target)
        strings_found = _extract_strings(payload, min_len=min_len, limit=limit)

        if not strings_found:
            context.console.print("[yellow]No printable strings found.[/yellow]")
            return 0

        table = Table(title="Strings Analyzer")
        table.add_column("#", style="cyan", no_wrap=True)
        table.add_column("String", style="white")

        for idx, value in enumerate(strings_found, start=1):
            row = value
            if _looks_sensitive(value):
                row = f"[bold yellow]{value}[/bold yellow]"
            table.add_row(str(idx), row)

        context.console.print(table)
        context.console.print(
            Panel(
                "Use suspicious strings as anchors for static/dynamic reversing.",
                title="Hint",
                border_style="magenta",
            )
        )
        return 0


plugin = StringsAnalyzerPlugin()


def _load_payload(target: str) -> bytes:
    """Read bytes from file target or treat target as raw text."""

    path = Path(target)
    if path.exists() and path.is_file():
        size = path.stat().st_size
        if size > MAX_BYTES:
            raise ValueError(f"Target file too large (max {MAX_BYTES} bytes)")
        return path.read_bytes()
    return target.encode("utf-8", errors="ignore")


def _extract_strings(data: bytes, *, min_len: int, limit: int) -> list[str]:
    """Extract printable strings from byte payload."""

    out: list[str] = []
    buf: list[str] = []

    for byte in data:
        char = chr(byte)
        if char in string.printable and byte not in {11, 12}:
            buf.append(char)
            continue

        if len(buf) >= min_len:
            out.append("".join(buf))
            if len(out) >= limit:
                return out
        buf = []

    if len(buf) >= min_len and len(out) < limit:
        out.append("".join(buf))

    return out


def _looks_sensitive(text: str) -> bool:
    """Detect strings likely relevant for exploitation or reversing."""

    lowered = text.lower()
    markers = ["flag", "pass", "token", "admin", "/bin/sh", "%x", "%s"]
    return any(marker in lowered for marker in markers)

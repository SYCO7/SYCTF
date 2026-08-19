"""Extract strings from classes.dex and flag interesting API usage."""

from __future__ import annotations

import argparse
import re
import zipfile
from pathlib import Path

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.flags.detector import FlagDetector

# Interesting API / class markers worth surfacing in reversing.
_INTEREST = {
    "crypto": [b"javax/crypto", b"Cipher", b"AES", b"DES", b"MessageDigest", b"SecretKeySpec"],
    "exec/reflect": [b"Runtime", b"exec", b"ProcessBuilder", b"java/lang/reflect", b"DexClassLoader"],
    "network": [b"HttpURLConnection", b"okhttp", b"retrofit", b"WebView", b"loadUrl"],
    "storage": [b"SharedPreferences", b"SQLiteDatabase", b"openFileOutput"],
    "root/anti": [b"su", b"isDeviceRooted", b"Xposed", b"frida", b"ptrace"],
}


class DexStringsPlugin:
    """Pull ASCII strings from DEX files and categorize notable APIs."""

    name = "dex-strings"
    description = "Extract classes.dex strings, detect flags and interesting APIs"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--file", required=True, help="Path to .apk or .dex")
        parser.add_argument("--min-len", type=int, default=5, help="Min string length")
        parser.add_argument("--grep", help="Only show strings matching this substring")

    def _dex_blobs(self, path: Path) -> list[bytes]:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                return [zf.read(n) for n in zf.namelist() if n.endswith(".dex")]
        return [path.read_bytes()]

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        path = Path(args.file).expanduser()
        if not path.is_file():
            context.console.print("[bold red]File not found.[/bold red]")
            return 2

        context.logger.info("DEX strings file=%s", path)
        try:
            blobs = self._dex_blobs(path)
        except (zipfile.BadZipFile, OSError) as exc:
            context.console.print(f"[bold red]Read error:[/bold red] {exc}")
            return 1
        if not blobs:
            context.console.print("[yellow]No .dex found.[/yellow]")
            return 0

        joined = b"\n".join(blobs)
        min_len = max(4, int(args.min_len))
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        strings = [s.decode("ascii", "ignore") for s in pattern.findall(joined)]

        # flags
        detector = FlagDetector()
        flags = {h.value for h in detector.scan("\n".join(strings)) if h.real}
        if flags:
            context.console.print("[bold green]Possible flags:[/bold green]")
            for flag in sorted(flags):
                context.console.print(f"  - {flag}")
            context.cache["flag"] = sorted(flags)[0]

        # interesting API categories
        table = Table(title="Interesting APIs in DEX")
        table.add_column("Category", style="cyan")
        table.add_column("Markers hit", style="yellow")
        any_hit = False
        for category, markers in _INTEREST.items():
            hit = [m.decode() for m in markers if m in joined]
            if hit:
                any_hit = True
                table.add_row(category, ", ".join(hit))
        if any_hit:
            context.console.print(table)

        if args.grep:
            needle = str(args.grep).lower()
            matches = sorted({s for s in strings if needle in s.lower()})[:100]
            grep_table = Table(title=f"Strings matching '{args.grep}' ({len(matches)})")
            grep_table.add_column("String", style="green")
            for s in matches:
                grep_table.add_row(s[:160])
            context.console.print(grep_table)
        else:
            context.console.print(f"[dim]{len(strings)} strings extracted; use --grep to filter.[/dim]")
        return 0


plugin = DexStringsPlugin()

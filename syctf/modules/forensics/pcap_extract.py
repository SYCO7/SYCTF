"""Extract strings, credentials, and flags from a classic .pcap capture."""

from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.flags.detector import FlagDetector

# Raw first-4-bytes -> struct endianness of the file.
_PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4": ">",  # big-endian, microsecond
    b"\xa1\xb2\x3c\x4d": ">",  # big-endian, nanosecond
    b"\xd4\xc3\xb2\xa1": "<",  # little-endian, microsecond
    b"\x4d\x3c\xb2\xa1": "<",  # little-endian, nanosecond
}
_STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")
_INTEREST = re.compile(
    rb"(?i)(authorization:\s*\S+|password=\S+|passwd=\S+|user(?:name)?=\S+|"
    rb"GET\s+\S+\s+HTTP|POST\s+\S+\s+HTTP|Cookie:\s*\S+|flag)",
)


def iter_packets(data: bytes):
    """Yield raw packet payload bytes from a classic pcap blob."""

    if len(data) < 24:
        return
    endian = _PCAP_MAGIC.get(data[:4])
    if endian is None:
        raise ValueError("not a classic pcap (pcapng unsupported)")

    pos = 24  # skip global header
    while pos + 16 <= len(data):
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        if incl_len == 0 or pos + incl_len > len(data):
            break
        yield data[pos:pos + incl_len]
        pos += incl_len


class PcapExtractPlugin:
    """Pull ASCII, interesting headers, and flags out of a pcap."""

    name = "pcap-extract"
    description = "Extract strings, credentials, and flags from a classic .pcap"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--file", required=True, help="Path to .pcap")
        parser.add_argument("--grep", help="Only show strings containing this substring")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        path = Path(args.file).expanduser()
        if not path.is_file():
            context.console.print("[bold red]File not found.[/bold red]")
            return 2

        try:
            packets = list(iter_packets(path.read_bytes()))
        except ValueError as exc:
            context.console.print(f"[bold red]{exc}[/bold red]")
            return 1
        if not packets:
            context.console.print("[yellow]No packets parsed.[/yellow]")
            return 0

        context.logger.info("forensics pcap-extract file=%s packets=%d", path, len(packets))
        blob = b"\n".join(packets)
        detector = FlagDetector(custom_format=context.cache.get("flag_format"))

        flags = {h.value for h in detector.scan_bytes(blob) if h.real}
        if flags:
            context.console.print("[bold green]Flags:[/bold green]")
            for flag in sorted(flags):
                context.console.print(f"  - {flag}")
            context.cache["flag"] = sorted(flags)[0]

        interesting = sorted({m.decode("latin-1", "ignore") for m in _INTEREST.findall(blob)})
        if interesting:
            table = Table(title=f"Interesting ({len(interesting)})")
            table.add_column("Match", style="yellow")
            for item in interesting[:60]:
                table.add_row(item[:120])
            context.console.print(table)

        if args.grep:
            needle = str(args.grep).lower().encode()
            hits = sorted({m.decode("latin-1", "ignore") for m in _STRING_RE.findall(blob) if needle in m.lower()})[:100]
            grep_table = Table(title=f"Strings matching '{args.grep}' ({len(hits)})")
            grep_table.add_column("String", style="green")
            for s in hits:
                grep_table.add_row(s[:140])
            context.console.print(grep_table)
        else:
            context.console.print(f"[dim]{len(packets)} packets; use --grep to filter strings.[/dim]")
        return 0


plugin = PcapExtractPlugin()

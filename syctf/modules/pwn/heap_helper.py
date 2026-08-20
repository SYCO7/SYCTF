"""Heap exploitation helper: libc offsets, bin math, and libc-base from a leak.

Uses pyelftools to pull symbol/string offsets from a provided libc so you can
line up tcache/fastbin attacks and ret2libc quickly.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.table import Table

from syctf.core.types import ExecutionContext

_WANT = ["system", "execve", "__free_hook", "__malloc_hook", "__realloc_hook", "environ", "setcontext", "gets"]


def align_chunk(request: int) -> int:
    """Malloc usable-size -> real chunk size (glibc, 64-bit)."""

    size = request + 8               # + header/prev_size overlap
    size = (size + 15) & ~15
    return max(size, 0x20)


def tcache_index(chunk_size: int) -> int:
    """tcache bin index for a chunk size (64-bit): (size - 0x20) / 0x10."""

    return (chunk_size - 0x20) // 0x10


def fastbin_index(chunk_size: int) -> int:
    """fastbin index for a chunk size (64-bit): (size >> 4) - 2."""

    return (chunk_size >> 4) - 2


def libc_base(leak: int, symbol_offset: int) -> int:
    """Recover libc base from a leaked address of a known symbol."""

    return leak - symbol_offset


class HeapHelperPlugin:
    """Compute the numbers a heap exploit needs from a libc + a leak."""

    name = "heap-helper"
    description = "libc offsets, /bin/sh, tcache/fastbin math, libc-base from a leak"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--libc", required=True, help="Path to libc .so")
        parser.add_argument("--leak", help="Leaked address (dec or 0x) of --symbol")
        parser.add_argument("--symbol", default="__free_hook", help="Symbol the leak points at")
        parser.add_argument("--size", type=int, help="malloc request size -> chunk/bin class")

    def _symbols(self, libc: Path) -> dict[str, int]:
        from elftools.elf.elffile import ELFFile

        offsets: dict[str, int] = {}
        with libc.open("rb") as fh:
            elf = ELFFile(fh)
            for secname in (".dynsym", ".symtab"):
                sec = elf.get_section_by_name(secname)
                if sec is None:
                    continue
                for sym in sec.iter_symbols():
                    if sym.name in _WANT and sym["st_value"]:
                        offsets.setdefault(sym.name, sym["st_value"])
            # /bin/sh string offset
            for name in (".rodata", ".data"):
                sec = elf.get_section_by_name(name)
                if sec is None:
                    continue
                idx = sec.data().find(b"/bin/sh\x00")
                if idx != -1:
                    offsets["str:/bin/sh"] = sec["sh_addr"] + idx
                    break
        return offsets

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        try:
            from elftools.elf.elffile import ELFFile  # noqa: F401
        except ImportError:
            context.console.print("[bold red]pyelftools not installed (pip install pyelftools).[/bold red]")
            return 1

        libc = Path(args.libc).expanduser()
        if not libc.is_file():
            context.console.print("[bold red]libc not found.[/bold red]")
            return 2

        offsets = self._symbols(libc)
        if not offsets:
            context.console.print("[yellow]No useful symbols found in that libc.[/yellow]")

        base = None
        if args.leak:
            from syctf.utils.mathx import parse_int

            anchor = offsets.get(args.symbol)
            if anchor is None:
                context.console.print(f"[yellow]Symbol {args.symbol} not in libc; cannot anchor base.[/yellow]")
            else:
                base = libc_base(parse_int(args.leak), anchor)
                context.console.print(f"[bold green]libc base = {hex(base)}[/bold green]  (from {args.symbol}@{hex(anchor)})")

        table = Table(title=f"libc offsets — {libc.name}")
        table.add_column("Symbol", style="cyan", no_wrap=True)
        table.add_column("Offset", style="green")
        if base is not None:
            table.add_column("Absolute", style="yellow")
        for name in sorted(offsets):
            row = [name, hex(offsets[name])]
            if base is not None:
                row.append(hex(base + offsets[name]))
            table.add_row(*row)
        context.console.print(table)
        context.cache["libc_offsets"] = offsets

        if args.size is not None:
            chunk = align_chunk(int(args.size))
            context.console.print(
                f"[bold]request {args.size}[/bold] -> chunk size {hex(chunk)} "
                f"· tcache idx {tcache_index(chunk)} · fastbin idx {fastbin_index(chunk)}"
            )
        return 0


plugin = HeapHelperPlugin()

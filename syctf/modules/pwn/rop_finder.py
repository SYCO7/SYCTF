"""ROP gadget finder for ELF binaries (pattern-based, uses pyelftools).

No ropper/pwntools needed: scans executable sections for common gadget byte
patterns and reports their virtual addresses. Great for quick ret2libc / SROP
setup in CTF pwn.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.table import Table

from syctf.core.types import ExecutionContext

# name -> gadget byte pattern (x86 / x86-64)
_GADGETS_64 = {
    "ret": b"\xc3",
    "pop rdi; ret": b"\x5f\xc3",
    "pop rsi; ret": b"\x5e\xc3",
    "pop rdx; ret": b"\x5a\xc3",
    "pop rax; ret": b"\x58\xc3",
    "pop rbp; ret": b"\x5d\xc3",
    "pop rsp; ret": b"\x5c\xc3",
    "pop rsi; pop r15; ret": b"\x5e\x41\x5f\xc3",
    "leave; ret": b"\xc9\xc3",
    "syscall": b"\x0f\x05",
    "syscall; ret": b"\x0f\x05\xc3",
    "jmp rsp": b"\xff\xe4",
    "call rsp": b"\xff\xd4",
}
_GADGETS_32 = {
    "ret": b"\xc3",
    "pop eax; ret": b"\x58\xc3",
    "pop ebx; ret": b"\x5b\xc3",
    "pop ecx; ret": b"\x59\xc3",
    "pop edx; ret": b"\x5a\xc3",
    "pop esi; ret": b"\x5e\xc3",
    "pop edi; ret": b"\x5f\xc3",
    "pop ebp; ret": b"\x5d\xc3",
    "leave; ret": b"\xc9\xc3",
    "int 0x80": b"\xcd\x80",
    "jmp esp": b"\xff\xe4",
}


class RopFinderPlugin:
    """Find ROP gadgets and useful strings/symbols in an ELF."""

    name = "rop-finder"
    description = "Find ROP gadgets, /bin/sh, and syscall stubs in an ELF (no ropper needed)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--file", required=True, help="Path to ELF binary")
        parser.add_argument("--max-per-gadget", type=int, default=5, help="Max addresses shown per gadget")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError:
            context.console.print("[bold red]pyelftools not installed (pip install pyelftools).[/bold red]")
            return 1

        path = Path(args.file).expanduser()
        if not path.is_file():
            context.console.print("[bold red]File not found.[/bold red]")
            return 2

        context.logger.info("pwn rop-finder file=%s", path)
        try:
            with path.open("rb") as fh:
                elf = ELFFile(fh)
                bits = 64 if elf.elfclass == 64 else 32
                pie = elf.header["e_type"] == "ET_DYN"
                exec_sections = []
                for section in elf.iter_sections():
                    flags = section["sh_flags"]
                    if flags & 0x4:  # SHF_EXECINSTR
                        exec_sections.append((section["sh_addr"], section.data()))
                binsh = self._find_string(elf)
        except Exception as exc:  # noqa: BLE001 - malformed ELF
            context.console.print(f"[bold red]ELF parse error:[/bold red] {exc}")
            return 1

        gadgets = _GADGETS_64 if bits == 64 else _GADGETS_32
        results: dict[str, list[int]] = {}
        for name, pattern in gadgets.items():
            addrs: list[int] = []
            for base_addr, data in exec_sections:
                start = 0
                while True:
                    idx = data.find(pattern, start)
                    if idx == -1:
                        break
                    addrs.append(base_addr + idx)
                    start = idx + 1
                    if len(addrs) >= args.max_per_gadget:
                        break
                if len(addrs) >= args.max_per_gadget:
                    break
            if addrs:
                results[name] = addrs

        context.console.print(f"[bold]ELF:[/bold] {path.name}  arch={bits}-bit  PIE={pie}")
        if pie:
            context.console.print("[yellow]PIE binary: addresses are offsets from the load base.[/yellow]")

        table = Table(title="ROP gadgets")
        table.add_column("Gadget", style="cyan", no_wrap=True)
        table.add_column("Addresses", style="green")
        for name, addrs in results.items():
            table.add_row(name, "  ".join(hex(a) for a in addrs))
        context.console.print(table)

        if binsh is not None:
            context.console.print(f"[bold green]\"/bin/sh\" @ {hex(binsh)}[/bold green]")
        context.cache["rop_gadgets"] = {k: v[0] for k, v in results.items()}
        return 0

    def _find_string(self, elf) -> int | None:
        needle = b"/bin/sh\x00"
        for section in elf.iter_sections():
            try:
                data = section.data()
            except Exception:  # noqa: BLE001
                continue
            idx = data.find(needle)
            if idx != -1 and section["sh_addr"]:
                return section["sh_addr"] + idx
        return None


plugin = RopFinderPlugin()

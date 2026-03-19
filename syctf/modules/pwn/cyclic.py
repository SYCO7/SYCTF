"""Cyclic pattern generation and offset lookup module."""

from __future__ import annotations

import argparse
import re
import string
import subprocess
from pathlib import Path

from syctf.core.types import ExecutionContext

try:
    from pwn import *  # noqa: F401,F403

    PWNLIB_AVAILABLE = True
except ImportError:
    PWNLIB_AVAILABLE = False


def generate_cyclic(length: int) -> str:
    """Generate a deterministic cyclic pattern similar to pwntools."""

    charset_a = string.ascii_uppercase
    charset_b = string.ascii_lowercase
    charset_c = string.digits
    output: list[str] = []

    for a in charset_a:
        for b in charset_b:
            for c in charset_c:
                output.append(a)
                output.append(b)
                output.append(c)
                if len(output) >= length:
                    return "".join(output[:length])
    return "".join(output[:length])


def find_offset(pattern: str, needle: str) -> int:
    """Find offset by direct match or little-endian hex interpretation."""

    direct = pattern.find(needle)
    if direct >= 0:
        return direct

    candidate = needle.lower().strip()
    if candidate.startswith("0x"):
        candidate = candidate[2:]
    if len(candidate) % 2 == 0 and all(ch in string.hexdigits for ch in candidate):
        bytes_le = bytes.fromhex(candidate)
        try:
            text_le = bytes_le[::-1].decode("latin-1")
        except UnicodeDecodeError:
            return -1
        return pattern.find(text_le)
    return -1


class CyclicPlugin:
    """Generate cyclic payloads and locate crash offsets."""

    name = "cyclic"
    description = "Generate cyclic patterns or find offsets"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register plugin arguments."""

        parser.add_argument("action", choices=["generate", "find", "auto"], help="Operation")
        parser.add_argument("binary", nargs="?", help="Target binary path (for action=auto)")
        parser.add_argument("--length", type=int, default=256, help="Pattern length")
        parser.add_argument("--value", help="Search value (substring or hex)")
        parser.add_argument(
            "--register",
            default="rip",
            choices=["rip", "eip"],
            help="Register to extract from core dump in auto mode",
        )

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Execute pattern generation or offset finding."""

        if args.length < 1 or args.length > 100000:
            raise ValueError("length must be between 1 and 100000")

        pattern = generate_cyclic(args.length)
        if args.action == "generate":
            context.console.print(pattern)
            return 0

        if args.action == "auto":
            binary = args.binary or str(context.cache.get("target", "")).strip() or None
            if not binary:
                raise ValueError("Binary path required (argument or shell: set target ./chall)")
            return _auto_offset(binary, pattern, args.register, context)

        if not args.value:
            raise ValueError("--value is required for action=find")
        offset = find_offset(pattern, args.value)
        if offset < 0:
            context.console.print("[red]Value not found in generated pattern.[/red]")
            return 1
        context.console.print(f"[bold green]Offset:[/bold green] {offset}")
        return 0


def _auto_offset(binary_path: str, pattern: str, register: str, context: ExecutionContext) -> int:
    """Crash binary with cyclic payload, parse register from core, and compute offset."""

    binary = Path(binary_path).expanduser().resolve()
    if not binary.exists() or not binary.is_file():
        raise ValueError(f"Binary not found: {binary}")

    gdb = _which_command(["gdb"])
    if gdb is None:
        context.console.print("[bold red]gdb not found. Install gdb for cyclic auto mode.[/bold red]")
        return 1

    workdir = binary.parent
    payload = (pattern + "\n").encode("latin-1", errors="ignore")

    with context.console.status("[cyan]Launching binary with cyclic payload...[/cyan]", spinner="dots"):
        subprocess.run(
            [str(binary)],
            input=payload,
            capture_output=True,
            cwd=str(workdir),
            check=False,
            timeout=6.0,
        )

    core_file = _find_core_file(workdir)
    if core_file is None:
        context.console.print("[yellow]No core dump found. Enable core dumps and retry.[/yellow]")
        return 1

    reg_value = _extract_register_from_core(gdb, binary, core_file, register)
    if not reg_value:
        context.console.print("[red]Failed to extract crash register from core dump.[/red]")
        return 1

    offset = find_offset(pattern, reg_value)
    if offset < 0:
        context.console.print(f"[yellow]Could not find register value in pattern: {reg_value}[/yellow]")
        return 1

    context.console.print(f"[bold green]Auto offset found:[/bold green] {offset}")
    context.console.print(f"[cyan]Register value:[/cyan] {reg_value}")
    context.cache["cyclic_auto_offset"] = offset
    return 0


def _find_core_file(directory: Path) -> Path | None:
    """Find latest likely core dump file in directory."""

    candidates = [
        item
        for item in directory.iterdir()
        if item.is_file() and (item.name == "core" or item.name.startswith("core."))
    ]
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: item.stat().st_mtime, reverse=True)[0]


def _extract_register_from_core(gdb: str, binary: Path, core_file: Path, register: str) -> str | None:
    """Extract register value from core using gdb batch mode."""

    try:
        proc = subprocess.run(
            [gdb, "-q", "-batch", str(binary), str(core_file), "-ex", "info registers"],
            capture_output=True,
            text=True,
            check=False,
            timeout=8.0,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if proc.returncode != 0:
        return None

    match = re.search(rf"\b{register}\b\s+0x([0-9a-fA-F]+)", proc.stdout)
    if not match:
        return None
    return match.group(1)


def _which_command(candidates: list[str]) -> str | None:
    """Return first available executable in PATH."""

    import shutil

    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


plugin = CyclicPlugin()

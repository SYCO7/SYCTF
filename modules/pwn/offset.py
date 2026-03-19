"""Automatic crash offset finder using pwntools cyclic/corefile workflow."""

from __future__ import annotations

import argparse
import platform
import re
import time
from pathlib import Path
from typing import Any

from rich.panel import Panel

name = "offset"
description = "Find crash offset via cyclic patterns (manual or auto)"

AUTO_PATTERN_LEN = 1000
MAX_TIMEOUT_SECONDS = 30.0


class OffsetPlugin:
    """Generate cyclic patterns and automatically recover crash offsets."""

    name = name
    description = description

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register offset command arguments."""

        parser.add_argument("action", choices=["generate", "find", "auto"], help="Operation mode")
        parser.add_argument("binary", nargs="?", help="Target binary path (required for auto)")
        parser.add_argument("--value", help="Register value for find mode (hex/int/bytes text)")
        parser.add_argument(
            "--register",
            choices=["rip", "eip"],
            default="rip",
            help="Crash register to extract in auto mode",
        )
        parser.add_argument(
            "--timeout",
            type=float,
            default=8.0,
            help="Process crash timeout in seconds (max 30)",
        )
        parser.add_argument(
            "--length",
            type=int,
            default=AUTO_PATTERN_LEN,
            help="Pattern length for generate/find modes",
        )

    def run(self, args: argparse.Namespace, context: Any) -> int:
        """Execute selected offset workflow."""

        pwntools = _load_pwntools(context)
        if pwntools is None:
            return 1

        cyclic = pwntools["cyclic"]
        cyclic_find = pwntools["cyclic_find"]

        if args.length < 1 or args.length > 200000:
            raise ValueError("length must be between 1 and 200000")

        if args.timeout <= 0 or args.timeout > MAX_TIMEOUT_SECONDS:
            raise ValueError("timeout must be > 0 and <= 30 seconds")

        if args.action == "generate":
            pattern = cyclic(args.length)
            context.console.print(_decode_pattern(pattern))
            return 0

        if args.action == "find":
            if not args.value:
                raise ValueError("--value is required for find mode")
            pattern = cyclic(args.length)
            offset = _find_manual_offset(cyclic_find, pattern, args.value)
            if offset < 0:
                context.console.print("[red]Could not resolve offset for supplied value.[/red]")
                return 1
            context.console.print(
                Panel(
                    f"[bold green]Offset Found:[/bold green] {offset}",
                    title="Offset Finder",
                    border_style="green",
                )
            )
            context.cache["offset_last"] = offset
            return 0

        return _auto_offset(args, context, pwntools)


def _load_pwntools(context: Any) -> dict[str, Any] | None:
    """Import pwntools lazily so CLI can fail gracefully when missing."""

    try:
        from pwn import context as pwn_context
        from pwn import cyclic
        from pwn import cyclic_find
        from pwn import process
    except Exception as exc:  # noqa: BLE001
        context.console.print(
            "[bold red]pwntools is required.[/bold red] Install with: pip install pwntools"
        )
        context.logger.exception("pwntools import failed: %s", exc)
        return None

    return {
        "context": pwn_context,
        "cyclic": cyclic,
        "cyclic_find": cyclic_find,
        "process": process,
    }


def _decode_pattern(pattern: bytes | str) -> str:
    """Normalize pattern to printable text output."""

    if isinstance(pattern, bytes):
        return pattern.decode("latin-1", errors="ignore")
    return str(pattern)


def _parse_find_value(value: str) -> int | bytes:
    """Parse find value from integer/hex/string forms."""

    token = value.strip()
    if not token:
        raise ValueError("value cannot be empty")

    if token.startswith("0x"):
        return int(token, 16)

    if re.fullmatch(r"\d+", token):
        return int(token, 10)

    # Optional plain hex bytes without 0x prefix.
    if re.fullmatch(r"[0-9a-fA-F]{8,16}", token):
        return int(token, 16)

    return token.encode("latin-1", errors="ignore")


def _find_manual_offset(cyclic_find: Any, pattern: bytes | str, value: str) -> int:
    """Resolve offset in find mode with robust fallback strategies."""

    needle = _parse_find_value(value)

    try:
        offset = int(cyclic_find(needle))
        if offset >= 0:
            return offset
    except Exception:  # noqa: BLE001
        pass

    raw_pattern = pattern if isinstance(pattern, bytes) else pattern.encode("latin-1", errors="ignore")
    raw_needle = needle if isinstance(needle, bytes) else str(needle).encode("latin-1", errors="ignore")
    manual = raw_pattern.find(raw_needle)
    return manual if manual >= 0 else -1


def _auto_offset(args: argparse.Namespace, context: Any, pwntools: dict[str, Any]) -> int:
    """Run binary with cyclic(1000), parse core register, and compute exact offset."""

    if platform.system().lower() != "linux":
        context.console.print(
            "[bold red]Auto corefile offset currently supports Linux targets only.[/bold red]"
        )
        return 1

    binary_raw = (args.binary or str(context.cache.get("target", "")).strip()).strip()
    if not binary_raw:
        raise ValueError("Binary path required: pwn-helper offset auto ./binary")

    binary = Path(binary_raw).expanduser().resolve()
    if not binary.exists() or not binary.is_file():
        raise ValueError(f"Binary not found: {binary}")

    process = pwntools["process"]
    pwn_context = pwntools["context"]
    cyclic = pwntools["cyclic"]
    cyclic_find = pwntools["cyclic_find"]

    pattern = cyclic(AUTO_PATTERN_LEN)
    io = None

    try:
        with pwn_context.local(log_level="error"):
            io = process([str(binary)], cwd=str(binary.parent))
            io.sendline(pattern)

            deadline = time.monotonic() + float(args.timeout)
            while time.monotonic() < deadline:
                status = io.poll(block=False)
                if status is not None:
                    break
                time.sleep(0.05)

            status = io.poll(block=False)
            if status is None:
                io.kill()
                context.console.print("[yellow]Process did not crash before timeout.[/yellow]")
                return 1

            # Negative status usually indicates signal-based crash.
            if status >= 0:
                context.console.print("[yellow]Process exited cleanly; no crash corefile available.[/yellow]")
                return 1

            try:
                core = io.corefile
            except Exception as exc:  # noqa: BLE001
                context.console.print(f"[red]Unable to load corefile: {exc}[/red]")
                return 1

            register_value = _extract_register_value(core, args.register)
            if register_value is None:
                context.console.print("[red]Failed to extract crash register from corefile.[/red]")
                return 1

            offset = _find_offset_from_register(cyclic_find, register_value, args.register)
            if offset < 0:
                context.console.print("[yellow]Register value was not found in cyclic(1000) pattern.[/yellow]")
                return 1

            context.cache["offset_last"] = offset
            context.cache["offset_register"] = args.register
            context.cache["offset_register_value"] = hex(register_value)

            context.console.print(
                Panel(
                    f"[bold green]Offset Found:[/bold green] {offset}\n"
                    f"[cyan]{args.register.upper()}:[/cyan] {hex(register_value)}\n"
                    f"[dim]Pattern: cyclic({AUTO_PATTERN_LEN})[/dim]",
                    title="Offset Finder",
                    border_style="green",
                )
            )
            return 0
    finally:
        if io is not None:
            try:
                io.close()
            except Exception:  # noqa: BLE001
                pass


def _extract_register_value(core: Any, register: str) -> int | None:
    """Extract integer register value from pwntools Corefile safely."""

    # Prefer arch-specific direct attributes.
    try:
        direct = getattr(core, register)
        if isinstance(direct, int):
            return direct
    except Exception:  # noqa: BLE001
        pass

    # Fallback: read from register mapping if available.
    try:
        registers = getattr(core, "registers", {})
        value = registers.get(register)
        if isinstance(value, int):
            return value
    except Exception:  # noqa: BLE001
        return None

    return None


def _find_offset_from_register(cyclic_find: Any, register_value: int, register: str) -> int:
    """Compute cyclic offset from register value using robust strategies."""

    if register == "eip":
        try:
            return int(cyclic_find(register_value & 0xFFFFFFFF))
        except Exception:  # noqa: BLE001
            return -1

    # RIP on 64-bit often needs truncation to first 4 bytes for default cyclic alphabet.
    strategies: list[Any] = [
        register_value,
        register_value & 0xFFFFFFFF,
        int.from_bytes((register_value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")[:4], "little"),
    ]

    for candidate in strategies:
        try:
            offset = int(cyclic_find(candidate))
            if offset >= 0:
                return offset
        except Exception:  # noqa: BLE001
            continue

    return -1


plugin = OffsetPlugin()

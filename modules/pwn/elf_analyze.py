"""Production ELF triage analyzer for exploitation workflows."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import re
import shutil
import string
import subprocess
from pathlib import Path
from typing import Any

from elftools.elf.constants import P_FLAGS, SH_FLAGS
from elftools.elf.elffile import ELFFile
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from syctf.core.cache_store import cache_key, load_json_cache, save_json_cache
from syctf.core.types import ExecutionContext

try:
    from pwn import *  # noqa: F401,F403

    PWNLIB_AVAILABLE = True
except ImportError:
    PWNLIB_AVAILABLE = False

name = "elf-analyze"
description = "Professional ELF triage analyzer with exploitability hints"

DANGEROUS_FUNCTIONS = {"gets", "scanf", "strcpy", "system", "read", "printf"}
FORMAT_REGEX = re.compile(r"%[0-9$#\-\.\*]*[duxXscpfn]", re.IGNORECASE)
STRING_MARKERS = ["/bin/sh", "flag", "input"]
MAX_BINARY_SIZE = 100_000_000
MAX_STRINGS = 50


def _validate_elf(path_raw: str) -> Path:
    """Validate file path and ELF magic before analysis."""

    path = Path(path_raw).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise ValueError(f"Binary does not exist: {path}")
    if path.stat().st_size > MAX_BINARY_SIZE:
        raise ValueError("Binary is too large for safe analysis")

    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic != b"\x7fELF":
        raise ValueError("Target is not an ELF binary")
    return path


def _extract_strings(data: bytes, min_len: int = 4, limit: int = MAX_STRINGS) -> list[str]:
    """Extract printable strings from raw bytes."""

    out: list[str] = []
    buf: list[str] = []
    for byte in data:
        ch = chr(byte)
        if ch in string.printable and byte not in {11, 12}:
            buf.append(ch)
            continue

        if len(buf) >= min_len:
            out.append("".join(buf))
            if len(out) >= limit:
                return out
        buf = []

    if len(buf) >= min_len and len(out) < limit:
        out.append("".join(buf))
    return out


def _collect_function_symbols(elf: ELFFile) -> list[str]:
    """Collect function symbol names from symtab and dynsym."""

    names: set[str] = set()
    for section_name in (".symtab", ".dynsym"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            if symbol["st_info"]["type"] != "STT_FUNC":
                continue
            symbol_name = symbol.name.strip()
            if symbol_name:
                names.add(symbol_name)
    return sorted(names)


def _checksec(elf: ELFFile, symbols: list[str]) -> dict[str, Any]:
    """Compute checksec-like protection profile."""

    nx_enabled = True
    relro_present = False
    bind_now = False

    for segment in elf.iter_segments():
        seg_type = segment["p_type"]
        if seg_type == "PT_GNU_STACK":
            nx_enabled = (segment["p_flags"] & P_FLAGS.PF_X) == 0
        if seg_type == "PT_GNU_RELRO":
            relro_present = True

    dynamic_section = elf.get_section_by_name(".dynamic")
    if dynamic_section is not None:
        for tag in dynamic_section.iter_tags():
            if tag.entry.d_tag == "DT_BIND_NOW":
                bind_now = True
            if tag.entry.d_tag == "DT_FLAGS":
                value = int(tag.entry.d_val)
                if value & 0x8:
                    bind_now = True

    relro = "None"
    if relro_present and bind_now:
        relro = "Full"
    elif relro_present:
        relro = "Partial"

    pie_enabled = elf.header["e_type"] == "ET_DYN"
    canary_enabled = "__stack_chk_fail" in symbols or "__stack_chk_guard" in symbols

    return {
        "nx": bool(nx_enabled),
        "pie": bool(pie_enabled),
        "canary": bool(canary_enabled),
        "relro": relro,
    }


def _got_plt_summary(elf: ELFFile) -> dict[str, Any]:
    """Summarize GOT/PLT properties for overwrite feasibility."""

    plt_entries = 0
    writable_got = False

    for section in elf.iter_sections():
        section_name = section.name
        if section_name.startswith(".plt"):
            entry_size = int(getattr(section, "header", {}).get("sh_entsize", 0) or 0)
            if entry_size > 0:
                plt_entries += int(section.data_size // entry_size)
            else:
                plt_entries += max(0, int(section.data_size) // 16)

        if section_name in {".got", ".got.plt"}:
            flags = int(section["sh_flags"])
            if flags & int(SH_FLAGS.SHF_WRITE):
                writable_got = True

    return {
        "writable_got": writable_got,
        "plt_entries": int(plt_entries),
    }


def _count_rop_gadgets(binary_path: Path, timeout_seconds: float = 8.0) -> int | None:
    """Count ROP gadgets via ROPgadget binary if available."""

    tool = shutil.which("ROPgadget") or shutil.which("ropgadget")
    if not tool:
        return None

    try:
        proc = subprocess.run(
            [tool, "--binary", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=max(1.0, timeout_seconds),
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if proc.returncode != 0:
        return None

    stdout = proc.stdout
    gadget_lines = [line for line in stdout.splitlines() if line.strip().startswith("0x") and " : " in line]
    if gadget_lines:
        return len(gadget_lines)

    for line in stdout.splitlines():
        lowered = line.lower().strip()
        if lowered.startswith("unique gadgets found"):
            tail = lowered.split(":", 1)[-1].strip()
            if tail.isdigit():
                return int(tail)
    return None


def _metadata(elf: ELFFile) -> dict[str, Any]:
    """Extract basic ELF metadata."""

    machine = str(elf.header["e_machine"])
    arch_map = {
        "EM_386": "x86",
        "EM_X86_64": "amd64",
        "EM_AARCH64": "aarch64",
        "EM_ARM": "arm",
        "EM_MIPS": "mips",
    }
    arch = arch_map.get(machine, machine)

    return {
        "arch": arch,
        "bits": int(elf.elfclass),
        "endianness": "little" if elf.little_endian else "big",
        "entrypoint": hex(int(elf.header["e_entry"])),
        "binary_type": str(elf.header["e_type"]),
    }


def _interesting_strings(strings_found: list[str]) -> list[str]:
    """Filter strings for high-value exploit hints and format strings."""

    out: list[str] = []
    for value in strings_found:
        lowered = value.lower()
        if any(marker in lowered for marker in STRING_MARKERS) or FORMAT_REGEX.search(value):
            out.append(value)
    return out[:MAX_STRINGS]


def _build_hints(prot: dict[str, Any], danger: list[str], got_plt: dict[str, Any]) -> list[str]:
    """Generate exploit strategy hints from triage findings."""

    hints: list[str] = []

    if (not prot["canary"]) and "gets" in danger:
        hints.append("No canary + gets detected: stack overflow likely.")
    if "system" in danger:
        hints.append("system() present: ret2libc viable.")
    if not prot["nx"]:
        hints.append("NX disabled: shellcode injection likely viable.")
    if not prot["pie"]:
        hints.append("GOT overwrite possible.")
    if prot["pie"]:
        hints.append("PIE enabled: leak address before ROP chain finalization.")
    if got_plt["writable_got"] and got_plt["plt_entries"] > 0:
        hints.append("Writable GOT + PLT available: consider GOT hijack primitives.")

    if not hints:
        hints.append("No immediate exploit primitive found; continue manual triage.")
    return hints


def analyze_elf(binary_path: str | Path) -> dict[str, Any]:
    """Run full ELF triage analysis and return structured JSON-like dict."""

    path = _validate_elf(str(binary_path))

    try:
        with path.open("rb") as handle:
            data = handle.read()
        with path.open("rb") as handle:
            elf = ELFFile(handle)

            meta = _metadata(elf)
            symbols = _collect_function_symbols(elf)
            danger = sorted(func for func in symbols if func in DANGEROUS_FUNCTIONS)
            prot = _checksec(elf, symbols)
            got_plt = _got_plt_summary(elf)

        strings_found = _extract_strings(data, min_len=4, limit=MAX_STRINGS)
        interesting = _interesting_strings(strings_found)
        rop_count = _count_rop_gadgets(path)
        hints = _build_hints(prot, danger, got_plt)

        return {
            **meta,
            "path": str(path),
            "nx": bool(prot["nx"]),
            "pie": bool(prot["pie"]),
            "canary": bool(prot["canary"]),
            "relro": str(prot["relro"]),
            "danger_funcs": danger,
            "strings": strings_found,
            "interesting_strings": interesting,
            "got_plt": got_plt,
            "rop_gadget_count": rop_count,
            "hints": hints,
        }
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Failed to analyze ELF: {exc}") from exc


def _run_with_timeout(path: Path, timeout_seconds: float) -> dict[str, Any]:
    """Run analyzer in bounded worker to prevent hangs on malformed binaries."""

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(analyze_elf, path)
        return future.result(timeout=max(1.0, float(timeout_seconds)))


def _bool_style(value: bool) -> str:
    """Render checksec booleans in colored rich format."""

    return "[green]Enabled[/green]" if value else "[red]Disabled[/red]"


def _render(console: Console, result: dict[str, Any]) -> None:
    """Render rich UX panels/tables for exploitation triage."""

    meta_table = Table(title="ELF Metadata")
    meta_table.add_column("Field", style="cyan", no_wrap=True)
    meta_table.add_column("Value", style="white")
    meta_table.add_row("Path", str(result["path"]))
    meta_table.add_row("Architecture", str(result["arch"]))
    meta_table.add_row("Bits", str(result["bits"]))
    meta_table.add_row("Endianness", str(result["endianness"]))
    meta_table.add_row("Entrypoint", str(result["entrypoint"]))
    meta_table.add_row("Binary Type", str(result["binary_type"]))

    sec_table = Table(title="Security Protections")
    sec_table.add_column("Protection", style="cyan", no_wrap=True)
    sec_table.add_column("Status", style="white")
    sec_table.add_row("NX", _bool_style(bool(result["nx"])))
    sec_table.add_row("PIE", _bool_style(bool(result["pie"])))
    sec_table.add_row("Canary", _bool_style(bool(result["canary"])))
    relro = str(result["relro"])
    relro_color = "green" if relro == "Full" else "yellow" if relro == "Partial" else "red"
    sec_table.add_row("RELRO", f"[{relro_color}]{relro}[/{relro_color}]")

    got_plt = result.get("got_plt", {})
    sec_table.add_row("Writable GOT", _bool_style(bool(got_plt.get("writable_got", False))))
    sec_table.add_row("PLT Entries", str(got_plt.get("plt_entries", 0)))

    danger_table = Table(title="Dangerous Functions")
    danger_table.add_column("Function", style="white")
    danger = list(result.get("danger_funcs", []))
    if not danger:
        danger_table.add_row("none")
    else:
        for func in danger:
            danger_table.add_row(f"[bold red]{func}[/bold red]")

    str_table = Table(title="Interesting Strings (Top 50)")
    str_table.add_column("String", style="white")
    interesting = list(result.get("interesting_strings", []))
    if not interesting:
        str_table.add_row("none")
    else:
        for item in interesting[:50]:
            str_table.add_row(item)

    rop_count = result.get("rop_gadget_count")
    rop_text = (
        f"[green]{rop_count}[/green]"
        if isinstance(rop_count, int)
        else "[yellow]ROPgadget unavailable[/yellow]"
    )

    hints = list(result.get("hints", []))
    hint_body = "\n".join(f"- {hint}" for hint in hints)

    console.print(Panel(meta_table, title="Metadata", border_style="cyan"))
    console.print(Panel(sec_table, title="Protections", border_style="cyan"))
    console.print(Panel(danger_table, title="Symbol Triage", border_style="magenta"))
    console.print(Panel(str_table, title="Strings Analysis", border_style="green"))
    console.print(Panel(f"ROP Gadgets: {rop_text}\n\n{hint_body}", title="Exploit Hints", border_style="yellow"))


def run(args: argparse.Namespace, context: ExecutionContext | None = None) -> int | dict[str, Any]:
    """Plugin entrypoint with timeout, safety guards, and rich rendering."""

    console = context.console if context is not None else Console()
    target = args.binary_path
    if not target and context is not None:
        target = str(context.cache.get("target", "")).strip() or None

    try:
        if not target:
            raise ValueError("Binary path required (argument or shell: set target ./chall)")
        path = _validate_elf(target)
        signature = f"{path}:{path.stat().st_size}:{path.stat().st_mtime_ns}"
        key = cache_key("elf_analyze", hashlib.sha256(signature.encode("utf-8", errors="ignore")).hexdigest())
        cached = load_json_cache(key)
        if isinstance(cached, dict) and cached.get("path"):
            result = cached
            result["cache_hit"] = True
        else:
            with console.status("[cyan]Analyzing ELF binary...[/cyan]", spinner="dots"):
                result = _run_with_timeout(path, timeout_seconds=float(args.timeout))
            save_json_cache(key, result)
    except concurrent.futures.TimeoutError:
        console.print("[bold red]ELF analysis timed out.[/bold red]")
        return 1
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]ELF analysis failed:[/bold red] {exc}")
        return 1

    if result.get("cache_hit"):
        console.print("[cyan]elf-analyze cache hit[/cyan]")

    _render(console, result)

    if context is not None:
        context.cache["elf_analyze_result"] = result
        return 0
    return result


class ElfAnalyzePlugin:
    """Plugin adapter for dynamic loader."""

    name = name
    description = description

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register CLI args for elf-analyze."""

        parser.add_argument("binary_path", nargs="?", help="Path to ELF binary")
        parser.add_argument("--timeout", type=float, default=10.0, help="Analyzer timeout in seconds")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Execute plugin entrypoint."""

        result = run(args, context=context)
        return int(result) if isinstance(result, int) else 0


plugin = ElfAnalyzePlugin()

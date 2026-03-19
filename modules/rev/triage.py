"""Fast static reverse-engineering triage for unknown binaries."""

from __future__ import annotations

import argparse
import math
import re
import string
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile
from rich.panel import Panel
from rich.table import Table

name = "triage"
description = "Fast binary triage: strings, ELF sections/symbols, magic, entropy"

MAX_FILE_SIZE = 100_000_000
MIN_LEN_DEFAULT = 4
STRINGS_LIMIT = 80

KEYWORD_PATTERNS: dict[str, re.Pattern[str]] = {
    "flag": re.compile(r"flag", re.IGNORECASE),
    "password": re.compile(r"password", re.IGNORECASE),
    "admin": re.compile(r"admin", re.IGNORECASE),
    "secret": re.compile(r"secret", re.IGNORECASE),
    "key": re.compile(r"\bkey\b", re.IGNORECASE),
    "http": re.compile(r"https?://", re.IGNORECASE),
    "format": re.compile(r"%[0-9$#\-\.\*]*[duxXscpfn]", re.IGNORECASE),
}

BASE64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")


class RevTriagePlugin:
    """Provide instant static triage insights from unknown binaries."""

    name = name
    description = description

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register triage command arguments."""

        parser.add_argument("target", nargs="?", help="Target file path")
        parser.add_argument("--min-len", type=int, default=MIN_LEN_DEFAULT, help="Minimum printable string length")
        parser.add_argument("--limit", type=int, default=STRINGS_LIMIT, help="Maximum highlighted strings")

    def run(self, args: argparse.Namespace, context: Any) -> int:
        """Execute static triage pipeline without running the target binary."""

        target = args.target or str(context.cache.get("target", "")).strip() or None
        if not target:
            raise ValueError("Target required (argument or shell: set target ./binary)")

        min_len = max(4, int(args.min_len))
        limit = max(1, min(STRINGS_LIMIT, int(args.limit)))

        path = _validate_target(target)
        blob = path.read_bytes()

        strings_found = _extract_strings(blob, min_len=min_len)
        highlights = _highlight_strings(strings_found, limit=limit)
        entropy = _shannon_entropy(blob)
        magic = _detect_magic(blob, strings_found)
        elf_info = _analyze_elf(path)

        _render_output(context.console, path, strings_found, highlights, entropy, magic, elf_info)

        context.cache["rev_triage_result"] = {
            "path": str(path),
            "entropy": round(entropy, 4),
            "strings_total": len(strings_found),
            "strings_highlights": highlights,
            "magic": magic,
            "elf": elf_info,
        }
        return 0


plugin = RevTriagePlugin()


def _validate_target(target: str) -> Path:
    """Validate target file path and enforce safe size limits."""

    path = Path(target).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise ValueError(f"Target file not found: {path}")

    size = path.stat().st_size
    if size <= 0:
        raise ValueError("Target file is empty")
    if size > MAX_FILE_SIZE:
        raise ValueError(f"Target too large ({size} bytes). Max allowed is {MAX_FILE_SIZE} bytes")
    return path


def _extract_strings(data: bytes, *, min_len: int) -> list[str]:
    """Extract printable strings from binary data."""

    out: list[str] = []
    buf: list[str] = []
    for byte in data:
        ch = chr(byte)
        if ch in string.printable and byte not in {11, 12}:
            buf.append(ch)
            continue

        if len(buf) >= min_len:
            out.append("".join(buf))
        buf = []

    if len(buf) >= min_len:
        out.append("".join(buf))
    return out


def _highlight_strings(strings_found: list[str], *, limit: int) -> list[str]:
    """Select and de-duplicate strings matching triage patterns."""

    selected: list[str] = []
    seen: set[str] = set()
    for text in strings_found:
        lowered = text.lower()
        if not any(pattern.search(lowered) for pattern in KEYWORD_PATTERNS.values()):
            continue

        cleaned = text.strip().replace("\r", "")
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        selected.append(cleaned[:220])
        if len(selected) >= limit:
            break
    return selected


def _detect_magic(data: bytes, strings_found: list[str]) -> dict[str, Any]:
    """Detect common packer/compression/encoding indicators."""

    head = data[:8192]
    has_upx = b"UPX!" in data or b"UPX0" in data or b"UPX1" in data
    has_gzip = head.startswith(b"\x1f\x8b")

    base64_blob = False
    for item in strings_found[:1200]:
        if BASE64_BLOB_RE.search(item):
            base64_blob = True
            break

    return {
        "upx_packed": has_upx,
        "gzip_compressed": has_gzip,
        "base64_blob": base64_blob,
    }


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy over byte distribution."""

    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    n = float(len(data))
    entropy = 0.0
    for count in freq:
        if count == 0:
            continue
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def _analyze_elf(path: Path) -> dict[str, Any]:
    """Analyze ELF sections and symbols safely, handling corruption."""

    info: dict[str, Any] = {
        "is_elf": False,
        "error": None,
        "sections": [],
        "suspicious_rwx": [],
        "rodata_size": 0,
        "bss_size": 0,
        "stripped": None,
        "interesting_symbols": [],
    }

    try:
        with path.open("rb") as handle:
            if handle.read(4) != b"\x7fELF":
                return info

        with path.open("rb") as handle:
            elf = ELFFile(handle)
            info["is_elf"] = True

            sections: list[dict[str, Any]] = []
            suspicious_rwx: list[str] = []
            rodata_size = 0
            bss_size = 0

            for section in elf.iter_sections():
                sec_name = section.name or "<unnamed>"
                size = int(section["sh_size"])
                flags = int(section["sh_flags"])
                sections.append({"name": sec_name, "size": size, "flags": flags})

                is_exec = bool(flags & 0x4)
                is_write = bool(flags & 0x1)
                is_alloc = bool(flags & 0x2)
                if is_exec and is_write and is_alloc:
                    suspicious_rwx.append(sec_name)

                if sec_name == ".rodata":
                    rodata_size = size
                if sec_name == ".bss":
                    bss_size = size

            info["sections"] = sections
            info["suspicious_rwx"] = suspicious_rwx
            info["rodata_size"] = rodata_size
            info["bss_size"] = bss_size

            symtab = elf.get_section_by_name(".symtab")
            dynsym = elf.get_section_by_name(".dynsym")
            info["stripped"] = symtab is None

            symbols: set[str] = set()
            for sym_section in (symtab, dynsym):
                if sym_section is None:
                    continue
                for symbol in sym_section.iter_symbols():
                    sym_name = (symbol.name or "").strip()
                    if not sym_name:
                        continue
                    symbols.add(sym_name)

            candidates = sorted(
                sym for sym in symbols if re.search(r"(^main$|win|vuln)", sym, re.IGNORECASE)
            )
            info["interesting_symbols"] = candidates[:30]

    except Exception as exc:  # noqa: BLE001
        info["error"] = f"ELF parse error: {exc}"

    return info


def _render_output(
    console,
    path: Path,
    strings_found: list[str],
    highlights: list[str],
    entropy: float,
    magic: dict[str, Any],
    elf_info: dict[str, Any],
) -> None:
    """Render triage result in rich panels and tables."""

    summary = Table(show_header=False)
    summary.add_column("Field", style="cyan", no_wrap=True)
    summary.add_column("Value", style="white")
    summary.add_row("Target", str(path))
    summary.add_row("Size (bytes)", str(path.stat().st_size))
    summary.add_row("Strings (>=4)", str(len(strings_found)))
    summary.add_row("Entropy", f"{entropy:.4f}")
    summary.add_row("Likely Packed", "yes" if entropy > 7.2 else "no")
    summary.add_row("UPX Packed", "yes" if magic.get("upx_packed") else "no")
    summary.add_row("Gzip Compressed", "yes" if magic.get("gzip_compressed") else "no")
    summary.add_row("Base64 Blob", "yes" if magic.get("base64_blob") else "no")

    if elf_info.get("is_elf"):
        summary.add_row("ELF", "yes")
        summary.add_row(".rodata size", str(elf_info.get("rodata_size", 0)))
        summary.add_row(".bss size", str(elf_info.get("bss_size", 0)))
        stripped = elf_info.get("stripped")
        summary.add_row("Stripped", "yes" if stripped else "no")
    else:
        summary.add_row("ELF", "no")

    strings_table = Table(title="Strings Highlights (max 80)")
    strings_table.add_column("#", style="cyan", no_wrap=True)
    strings_table.add_column("String", style="white")
    if not highlights:
        strings_table.add_row("-", "No keyword hits found")
    else:
        for idx, value in enumerate(highlights, start=1):
            strings_table.add_row(str(idx), value)

    suspicion_lines: list[str] = []
    if entropy > 7.2:
        suspicion_lines.append(f"- High entropy ({entropy:.4f}) suggests packed or encrypted data")
    if magic.get("upx_packed"):
        suspicion_lines.append("- UPX signature detected")
    if magic.get("gzip_compressed"):
        suspicion_lines.append("- Gzip magic header detected")
    if magic.get("base64_blob"):
        suspicion_lines.append("- Base64-like blob detected in printable strings")

    if elf_info.get("error"):
        suspicion_lines.append(f"- {elf_info['error']}")
    elif elf_info.get("is_elf"):
        rwx_sections = elf_info.get("suspicious_rwx", [])
        if rwx_sections:
            suspicion_lines.append(f"- Suspicious RWX sections: {', '.join(rwx_sections)}")
        else:
            suspicion_lines.append("- No suspicious RWX section detected")

        if elf_info.get("stripped"):
            suspicion_lines.append("- Binary appears stripped (no .symtab)")
        else:
            suspicion_lines.append("- Symbols present (not stripped)")

        symbols = elf_info.get("interesting_symbols", [])
        if symbols:
            suspicion_lines.append(f"- Interesting symbols: {', '.join(symbols[:10])}")
        else:
            suspicion_lines.append("- No main/win/vuln-like symbol names found")

    if not suspicion_lines:
        suspicion_lines.append("- No major suspicion indicators detected")

    section_preview = ""
    if elf_info.get("is_elf") and not elf_info.get("error"):
        sections = elf_info.get("sections", [])
        if sections:
            preview = []
            for row in sections[:20]:
                preview.append(f"{row['name']} (size={row['size']})")
            section_preview = "\nSections:\n" + "\n".join(f"- {item}" for item in preview)

    suspicion_body = "\n".join(suspicion_lines) + section_preview

    console.print(Panel(summary, title="Binary Summary", border_style="cyan"))
    console.print(Panel(strings_table, title="Strings Highlights", border_style="green"))
    console.print(Panel(suspicion_body, title="Suspicion Report", border_style="yellow"))

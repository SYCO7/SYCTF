"""ELF binary analyzer for exploit planning metadata."""

from __future__ import annotations

from pathlib import Path


def _detect_architecture(data: bytes) -> str:
    """Infer architecture from ELF e_machine field."""

    if len(data) < 20 or data[:4] != b"\x7fELF":
        return "unknown"

    e_machine = int.from_bytes(data[18:20], byteorder="little", signed=False)
    mapping = {
        0x03: "x86",
        0x3E: "x86_64",
        0x28: "arm",
        0xB7: "aarch64",
        0x08: "mips",
    }
    return mapping.get(e_machine, f"unknown(0x{e_machine:x})")


def _extract_strings(data: bytes, min_len: int = 4) -> set[str]:
    """Extract ASCII strings from binary data."""

    current: list[str] = []
    output: set[str] = set()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
            continue
        if len(current) >= min_len:
            output.add("".join(current))
        current = []

    if len(current) >= min_len:
        output.add("".join(current))
    return output


def analyze_elf(binary_path: str | Path) -> dict[str, object]:
    """Analyze ELF binary and return exploit-relevant metadata."""

    path = Path(binary_path).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise ValueError(f"Binary file does not exist: {path}")

    data = path.read_bytes()
    if len(data) > 100_000_000:
        raise ValueError("Binary is too large for safe analysis")
    if data[:4] != b"\x7fELF":
        raise ValueError("Target is not an ELF binary")

    extracted = _extract_strings(data)

    dynamic_markers = {".dynsym", ".dynamic", "__libc_start_main", "GLIBC_"}
    pie_markers = {"DYN", "_dl_runtime_resolve", ".got.plt", "R_X86_64_RELATIVE"}
    canary_markers = {"__stack_chk_fail", "__stack_chk_guard"}
    nx_markers = {"GNU_STACK", "__libc_start_main", "mprotect", "mmap"}

    dangerous_pool = [
        "gets",
        "strcpy",
        "strcat",
        "sprintf",
        "scanf",
        "fscanf",
        "sscanf",
        "read",
        "memcpy",
        "system",
        "popen",
        "execve",
    ]

    joined_blob = "\n".join(extracted)
    dangerous = sorted({name for name in dangerous_pool if name in joined_blob})

    has_dynamic = any(marker in joined_blob for marker in dynamic_markers)
    has_pie_hints = any(marker in joined_blob for marker in pie_markers)
    has_canary = any(marker in joined_blob for marker in canary_markers)
    has_nx_hints = any(marker in joined_blob for marker in nx_markers)

    metadata = {
        "path": str(path),
        "architecture": _detect_architecture(data),
        "nx": bool(has_nx_hints),
        "pie": bool(has_dynamic and has_pie_hints),
        "canary": bool(has_canary),
        "dangerous_functions": dangerous,
    }
    return metadata

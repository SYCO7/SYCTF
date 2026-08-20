"""Safe, dependency-light observation collectors.

These never execute untrusted binaries or arbitrary shell -- they only read and
analyse bytes. That keeps the autonomous loop grounded in real evidence while
staying safe to run unattended on a challenge you have not vetted.
"""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path

_MAGIC = {
    b"\x7fELF": "ELF executable",
    b"MZ": "PE/DOS executable",
    b"\x89PNG": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"PK\x03\x04": "ZIP/APK/JAR archive",
    b"Rar!": "RAR archive",
    b"\x1f\x8b": "gzip stream",
    b"BZh": "bzip2 stream",
    b"\xfd7zXZ": "xz stream",
    b"%PDF": "PDF document",
    b"OggS": "Ogg media",
    b"ID3": "MP3 audio",
    b"\xca\xfe\xba\xbe": "Java class / Mach-O fat",
    b"dex\n": "Android DEX",
    b"-----BEGIN": "PEM / key material",
}


def identify_file(path: Path) -> tuple[str, str]:
    """Return (summary, detail) describing the file type via magic bytes."""

    try:
        head = path.read_bytes()[:64]
    except OSError as exc:
        return (f"unreadable: {exc}", "")
    for magic, label in _MAGIC.items():
        if head.startswith(magic):
            return (label, f"magic={magic!r} size={path.stat().st_size}B")
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in head)
    ratio = printable / max(1, len(head))
    kind = "text/ascii" if ratio > 0.85 else "unknown binary"
    return (kind, f"printable_ratio={ratio:.2f} size={path.stat().st_size}B")


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (8.0 => random/encrypted/packed)."""

    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def entropy_report(path: Path) -> tuple[str, str]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return (f"unreadable: {exc}", "")
    ent = shannon_entropy(data[:1_000_000])
    hint = "high (packed/encrypted?)" if ent > 7.2 else "normal"
    return (f"entropy={ent:.2f} bits/byte ({hint})", f"bytes_sampled={min(len(data), 1_000_000)}")


def file_hashes(path: Path) -> tuple[str, str]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return (f"unreadable: {exc}", "")
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
    sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return ("hashes computed", f"md5={md5}\nsha1={sha1}\nsha256={sha256}")


def extract_strings(path: Path, *, min_len: int = 4, limit: int = 400) -> tuple[str, str]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return (f"unreadable: {exc}", "")
    runs = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    decoded = [r.decode("ascii", "ignore") for r in runs]
    shown = decoded[:limit]
    return (f"{len(decoded)} strings (showing {len(shown)})", "\n".join(shown))


def classify_text(text: str) -> tuple[str, str]:
    """Heuristically label a text blob to steer decoding."""

    stripped = text.strip()
    labels: list[str] = []
    if re.fullmatch(r"[A-Za-z0-9+/=\s]+", stripped) and len(stripped) >= 8 and "=" in stripped[-3:]:
        labels.append("base64-like")
    if re.fullmatch(r"[0-9a-fA-F\s]+", stripped) and len(stripped.replace(" ", "")) % 2 == 0:
        labels.append("hex-like")
    if re.fullmatch(r"[01\s]+", stripped):
        labels.append("binary-bits")
    if re.fullmatch(r"[.\-\s/]+", stripped):
        labels.append("morse-like")
    if not labels:
        labels.append("plaintext/unknown")
    return (", ".join(labels), stripped[:2000])

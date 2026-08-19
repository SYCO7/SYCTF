"""Flag detection across text and bytes."""

from __future__ import annotations

import re
from dataclasses import dataclass

from syctf.flags.patterns import compile_patterns, is_placeholder


@dataclass(slots=True)
class FlagHit:
    """One detected flag candidate and where it came from."""

    value: str
    source: str
    placeholder: bool


class FlagDetector:
    """Scans arbitrary output for flag-shaped strings."""

    def __init__(self, custom_format: str | None = None) -> None:
        self.patterns = compile_patterns(custom_format)

    def scan(self, text: str, *, source: str = "output") -> list[FlagHit]:
        """Return de-duplicated flag hits found in ``text``."""

        seen: dict[str, FlagHit] = {}
        for pattern in self.patterns:
            for match in pattern.finditer(text or ""):
                value = match.group(0).strip()
                if value in seen:
                    continue
                seen[value] = FlagHit(value=value, source=source, placeholder=is_placeholder(value))
        return list(seen.values())

    def scan_bytes(self, blob: bytes, *, source: str = "binary", min_len: int = 4) -> list[FlagHit]:
        """Extract printable runs from bytes, then scan them for flags."""

        printable = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, blob or b"")
        text = "\n".join(p.decode("ascii", "ignore") for p in printable)
        return self.scan(text, source=source)

    def best(self, hits: list[FlagHit]) -> FlagHit | None:
        """Pick the most trustworthy hit: real over placeholder, longest body."""

        real = [h for h in hits if not h.placeholder]
        pool = real or hits
        if not pool:
            return None
        return max(pool, key=lambda h: len(h.value))

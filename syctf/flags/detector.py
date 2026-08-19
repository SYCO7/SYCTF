"""Flag detection across text and bytes."""

from __future__ import annotations

import re
from dataclasses import dataclass

from syctf.flags.patterns import compile_patterns, is_decoy, is_placeholder


@dataclass(slots=True)
class FlagHit:
    """One detected flag candidate and where it came from."""

    value: str
    source: str
    placeholder: bool
    decoy: bool = False

    @property
    def real(self) -> bool:
        """A trustworthy candidate: neither a template nor a planted decoy."""

        return not self.placeholder and not self.decoy


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
                seen[value] = FlagHit(
                    value=value,
                    source=source,
                    placeholder=is_placeholder(value),
                    decoy=is_decoy(value),
                )
        return list(seen.values())

    def scan_bytes(self, blob: bytes, *, source: str = "binary", min_len: int = 4) -> list[FlagHit]:
        """Extract printable runs from bytes, then scan them for flags."""

        printable = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, blob or b"")
        text = "\n".join(p.decode("ascii", "ignore") for p in printable)
        return self.scan(text, source=source)

    def best(self, hits: list[FlagHit]) -> FlagHit | None:
        """Pick the best *real* flag: never a placeholder or a planted decoy.

        Returns None when every candidate is a template or a decoy — so the
        engine reports "no flag" instead of a fake one.
        """

        real = [h for h in hits if h.real]
        if not real:
            return None
        return max(real, key=lambda h: len(h.value))

    def decoys(self, hits: list[FlagHit]) -> list[FlagHit]:
        """Return the flag-shaped hits that look like planted decoys."""

        return [h for h in hits if h.decoy]

"""Flag format patterns and placeholder detection."""

from __future__ import annotations

import re

# Common CTF flag wrappers. ``{...}`` body is intentionally permissive but
# bounded to avoid runaway matches across whole files.
DEFAULT_FLAG_REGEXES: tuple[str, ...] = (
    r"[A-Za-z0-9_]{2,20}\{[^{}\n]{1,200}\}",   # generic  NAME{...}
    r"flag\{[^{}\n]{1,200}\}",
    r"CTF\{[^{}\n]{1,200}\}",
)

# Substrings that betray a fabricated / templated "flag" from an LLM.
PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "example", "placeholder", "your_flag", "yourflag", "redacted",
    "xxxx", "....", "flag_here", "flaghere", "the_flag", "some_flag",
    "insert", "todo", "changeme", "<", ">", "…",
)


def compile_patterns(custom_format: str | None = None) -> list[re.Pattern[str]]:
    """Return compiled flag patterns, optionally prepending a custom format.

    ``custom_format`` may be a full regex, or a simple ``NAME{}`` prefix such
    as ``picoCTF`` / ``picoCTF{}`` which is expanded automatically.
    """

    patterns: list[re.Pattern[str]] = []
    if custom_format:
        fmt = custom_format.strip()
        if "{" not in fmt and "\\" not in fmt:
            fmt = re.escape(fmt) + r"\{[^{}\n]{1,200}\}"
        elif fmt.endswith("{}"):
            fmt = re.escape(fmt[:-2]) + r"\{[^{}\n]{1,200}\}"
        try:
            patterns.append(re.compile(fmt))
        except re.error:
            pass
    for raw in DEFAULT_FLAG_REGEXES:
        patterns.append(re.compile(raw))
    return patterns


def is_placeholder(candidate: str) -> bool:
    """True when a flag-looking string is almost certainly a template."""

    low = candidate.lower()
    return any(marker in low for marker in PLACEHOLDER_MARKERS)

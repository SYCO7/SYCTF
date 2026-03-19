"""Configuration loading and validation for SYCTF."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from syctf.core.types import AppConfig


def _merge_config(raw: dict[str, Any]) -> AppConfig:
    """Create a validated AppConfig instance from raw data."""

    defaults = AppConfig()
    merged = asdict(defaults)
    for key, value in raw.items():
        if key in merged:
            merged[key] = value

    if not isinstance(merged["owner"], str):
        merged["owner"] = defaults.owner
    if not isinstance(merged["github"], str):
        merged["github"] = defaults.github
    if not isinstance(merged["linkedin"], str):
        merged["linkedin"] = defaults.linkedin
    if not isinstance(merged["portfolio"], str):
        merged["portfolio"] = defaults.portfolio

    merged["request_timeout"] = max(1.0, float(merged["request_timeout"]))
    merged["connect_timeout"] = max(0.2, float(merged["connect_timeout"]))
    merged["max_threads"] = max(1, min(500, int(merged["max_threads"])))

    default_wordlist = merged.get("default_wordlist", str(defaults.default_wordlist))
    merged["default_wordlist"] = Path(default_wordlist)

    return AppConfig(**merged)


def load_config(path: Path) -> AppConfig:
    """Load .syctfconfig JSON file from disk or return defaults."""

    if not path.exists():
        return AppConfig()

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return AppConfig()

    if not isinstance(raw, dict):
        return AppConfig()

    return _merge_config(raw)

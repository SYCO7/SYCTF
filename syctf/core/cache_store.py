"""Persistent lightweight JSON cache helpers for SYCTF."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from syctf.core.paths import get_cache_dir


def cache_key(namespace: str, payload: str) -> str:
    """Build deterministic cache key from namespace and payload text."""

    digest = hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()
    safe_ns = namespace.strip().replace("/", "_")
    return f"{safe_ns}:{digest}"


def _cache_path(key: str) -> Path:
    """Resolve cache path for key under ~/.syctf/cache/."""

    namespace, _, digest = key.partition(":")
    base = get_cache_dir() / (namespace or "default")
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{digest or 'unknown'}.json"


def load_json_cache(key: str) -> dict[str, Any] | None:
    """Load cached JSON object by key, returning None when unavailable."""

    path = _cache_path(key)
    if not path.exists() or not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def save_json_cache(key: str, payload: dict[str, Any]) -> None:
    """Persist JSON cache payload atomically-ish for simple reuse."""

    path = _cache_path(key)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    temp.replace(path)

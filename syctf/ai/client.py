"""Centralized Ollama client factory for SYCTF AI modules."""

from __future__ import annotations

import os

import ollama

_DEFAULT_HOST = "http://127.0.0.1:11434"
_DEFAULT_TIMEOUT_SECONDS = 30.0


def get_ollama_host() -> str:
    """Return normalized Ollama host from environment configuration."""

    host = os.environ.get("OLLAMA_HOST", _DEFAULT_HOST).strip()
    if not host:
        host = _DEFAULT_HOST
    if not host.startswith("http"):
        host = "http://" + host
    return host


def _read_timeout_seconds() -> float:
    """Read optional client timeout from environment with safe fallback."""

    raw = os.environ.get("SYCTF_OLLAMA_TIMEOUT", "").strip()
    if not raw:
        return _DEFAULT_TIMEOUT_SECONDS
    try:
        timeout = float(raw)
    except ValueError:
        print(
            f"[SYCTF AI] Invalid SYCTF_OLLAMA_TIMEOUT={raw!r}; "
            f"using default {_DEFAULT_TIMEOUT_SECONDS:.1f}s"
        )
        return _DEFAULT_TIMEOUT_SECONDS

    if timeout <= 0:
        print(
            f"[SYCTF AI] Non-positive SYCTF_OLLAMA_TIMEOUT={raw!r}; "
            f"using default {_DEFAULT_TIMEOUT_SECONDS:.1f}s"
        )
        return _DEFAULT_TIMEOUT_SECONDS
    return timeout


def get_ollama_client(timeout: float | None = None) -> ollama.Client:
    """Build and return a configured Ollama client instance."""

    host = get_ollama_host()

    if timeout is None:
        timeout = _read_timeout_seconds()

    print(f"[SYCTF AI] Using Ollama host: {host}")

    return ollama.Client(host=host, timeout=float(timeout))

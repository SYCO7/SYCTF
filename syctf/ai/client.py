"""Centralized Ollama client factory for SYCTF AI modules."""

from __future__ import annotations

import os
from dataclasses import dataclass

import ollama

from syctf.ai.ollama_resolver import OllamaDiagnostics, OllamaResolver, OllamaResolverError

_DEFAULT_TIMEOUT_SECONDS = 30.0


@dataclass(slots=True)
class AIConnectionDiagnostics:
    """Normalized AI connection diagnostics used by startup flows."""

    connected_host: str | None
    latency_ms: float | None
    model_available: bool
    available_models: list[str]


def get_ollama_host() -> str:
    """Resolve and return active Ollama host from configured candidates."""

    resolver = OllamaResolver()
    return resolver.resolve()


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


def get_ai_connection_diagnostics(model: str) -> AIConnectionDiagnostics:
    """Return resolved host, latency, and model-availability diagnostics."""

    resolver = OllamaResolver()
    data: OllamaDiagnostics = resolver.diagnostics(model=model)
    return AIConnectionDiagnostics(
        connected_host=data.connected_host,
        latency_ms=data.latency_ms,
        model_available=data.model_available,
        available_models=list(data.available_models),
    )


__all__ = [
    "AIConnectionDiagnostics",
    "OllamaResolverError",
    "get_ai_connection_diagnostics",
    "get_ollama_client",
    "get_ollama_host",
]

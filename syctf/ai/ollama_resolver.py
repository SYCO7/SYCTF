"""Ollama host discovery, probing, and diagnostics for SYCTF."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

import httpx

_DEFAULT_CANDIDATES = [
    "http://127.0.0.1:11434",
    "http://localhost:11434",
    "http://10.0.2.2:11434",
    "http://host.docker.internal:11434",
]


class OllamaResolverError(RuntimeError):
    """Raised when no reachable Ollama endpoint is discovered."""


@dataclass(slots=True)
class OllamaProbeResult:
    """Probe result details for one host candidate."""

    host: str
    ok: bool
    latency_ms: float | None


@dataclass(slots=True)
class OllamaDiagnostics:
    """Resolved host diagnostics for rendering and health checks."""

    connected_host: str | None
    latency_ms: float | None
    model_available: bool
    available_models: list[str]


class OllamaResolver:
    """Resolve a reachable Ollama host from ordered, safe candidates."""

    _cached_host: str | None = None
    _cached_latency_ms: float | None = None

    def get_candidate_hosts(self) -> list[str]:
        """Return ordered host candidates, preferring OLLAMA_HOST when set."""

        ordered: list[str] = []
        seen: set[str] = set()

        env_host = self._normalize_host(os.environ.get("OLLAMA_HOST", ""))
        if env_host:
            ordered.append(env_host)
            seen.add(env_host)

        for host in _DEFAULT_CANDIDATES:
            normalized = self._normalize_host(host)
            if not normalized or normalized in seen:
                continue
            ordered.append(normalized)
            seen.add(normalized)

        return ordered

    def probe_host(self, host: str) -> OllamaProbeResult:
        """Probe one host by requesting /api/tags with a short timeout."""

        normalized = self._normalize_host(host)
        if not normalized:
            return OllamaProbeResult(host=str(host), ok=False, latency_ms=None)

        started = time.perf_counter()
        try:
            with httpx.Client(timeout=1.5, follow_redirects=False) as client:
                response = client.get(f"{normalized}/api/tags")
            latency_ms = (time.perf_counter() - started) * 1000.0
            if response.status_code == 200:
                return OllamaProbeResult(host=normalized, ok=True, latency_ms=latency_ms)
            return OllamaProbeResult(host=normalized, ok=False, latency_ms=latency_ms)
        except httpx.HTTPError:
            return OllamaProbeResult(host=normalized, ok=False, latency_ms=None)

    def resolve(self) -> str:
        """Resolve and cache the first reachable Ollama host."""

        if self.__class__._cached_host:
            return str(self.__class__._cached_host)

        for host in self.get_candidate_hosts():
            probe = self.probe_host(host)
            if probe.ok:
                self.__class__._cached_host = probe.host
                self.__class__._cached_latency_ms = probe.latency_ms
                return probe.host

        raise OllamaResolverError(
            "Ollama not reachable. Start Ollama locally or configure OLLAMA_HOST."
        )

    def diagnostics(self, model: str) -> OllamaDiagnostics:
        """Resolve host and fetch model availability diagnostics."""

        try:
            host = self.resolve()
        except OllamaResolverError:
            return OllamaDiagnostics(
                connected_host=None,
                latency_ms=None,
                model_available=False,
                available_models=[],
            )

        available_models = self._fetch_models(host)
        return OllamaDiagnostics(
            connected_host=host,
            latency_ms=self.__class__._cached_latency_ms,
            model_available=model in available_models,
            available_models=available_models,
        )

    @staticmethod
    def _fetch_models(host: str) -> list[str]:
        """Fetch model list from resolved host using Ollama tags endpoint."""

        try:
            with httpx.Client(timeout=2.0, follow_redirects=False) as client:
                response = client.get(f"{host}/api/tags")
                if response.status_code != 200:
                    return []
                payload = response.json()
        except (httpx.HTTPError, ValueError):
            return []

        models_raw = payload.get("models", []) if isinstance(payload, dict) else []
        out: list[str] = []
        for item in models_raw:
            name = ""
            if isinstance(item, str):
                name = item
            elif isinstance(item, dict):
                name = str(item.get("model") or item.get("name") or "")
            name = name.strip()
            if name and name not in out:
                out.append(name)
        return out

    @staticmethod
    def _normalize_host(raw: str) -> str:
        """Normalize host values into canonical http://host:port form."""

        value = str(raw or "").strip().rstrip("/")
        if not value:
            return ""
        if not value.startswith("http://") and not value.startswith("https://"):
            value = "http://" + value
        return value

"""Anthropic Messages API adapter (Claude models)."""

from __future__ import annotations

import time
from typing import Any

import httpx

from syctf.ai.providers.base import BaseProvider, ChatResult, Message, ProviderError, split_system

_API_VERSION = "2023-06-01"


class AnthropicProvider(BaseProvider):
    """Talks the Anthropic ``/messages`` wire format over plain HTTP."""

    name = "anthropic"

    def __init__(self, *, model: str, base_url: str, api_key: str | None = None) -> None:
        super().__init__(model=model, api_key=api_key, base_url=base_url)

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "x-api-key": self.api_key or "",
            "anthropic-version": _API_VERSION,
        }

    def chat(
        self,
        messages: list[Message],
        *,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        timeout: float = 60.0,
        **kwargs: Any,
    ) -> ChatResult:
        system, rest = split_system(messages)
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": m["role"], "content": m["content"]} for m in rest],
        }
        if system:
            payload["system"] = system
        payload.update({k: v for k, v in kwargs.items() if v is not None})

        url = f"{self.base_url}/messages"
        started = time.perf_counter()
        try:
            response = httpx.post(url, json=payload, headers=self._headers(), timeout=timeout)
        except httpx.HTTPError as exc:
            raise ProviderError(f"anthropic: request failed: {exc}") from exc

        if response.status_code >= 400:
            raise ProviderError(f"anthropic: HTTP {response.status_code}: {response.text[:400]}")

        try:
            data = response.json()
            blocks = data.get("content", [])
            text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        except (ValueError, AttributeError) as exc:
            raise ProviderError(f"anthropic: malformed response: {response.text[:400]}") from exc

        return ChatResult(
            text=text,
            provider=self.name,
            model=data.get("model", self.model),
            finish_reason=data.get("stop_reason"),
            usage=data.get("usage", {}) or {},
            latency_ms=(time.perf_counter() - started) * 1000.0,
            raw=data,
        )

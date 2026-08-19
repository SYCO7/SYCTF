"""OpenAI-compatible chat adapter.

Covers OpenAI, Groq, NVIDIA NIM, OpenRouter, DeepSeek, Mistral, Together,
Fireworks, Cerebras, xAI, Perplexity, SambaNova, LM Studio, vLLM -- anything
exposing ``POST {base}/chat/completions`` with a Bearer key.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from syctf.ai.providers.base import BaseProvider, ChatResult, Message, ProviderError


class OpenAICompatibleProvider(BaseProvider):
    """Talks the OpenAI Chat Completions wire format over plain HTTP."""

    def __init__(self, *, name: str, model: str, base_url: str, api_key: str | None = None) -> None:
        super().__init__(model=model, api_key=api_key, base_url=base_url)
        self.name = name

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        # OpenRouter appreciates attribution headers; harmless elsewhere.
        headers.setdefault("HTTP-Referer", "https://github.com/SYCO7/SYCTF")
        headers.setdefault("X-Title", "SYCTF")
        return headers

    def chat(
        self,
        messages: list[Message],
        *,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        timeout: float = 60.0,
        **kwargs: Any,
    ) -> ChatResult:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        payload.update({k: v for k, v in kwargs.items() if v is not None})

        url = f"{self.base_url}/chat/completions"
        started = time.perf_counter()
        try:
            response = httpx.post(url, json=payload, headers=self._headers(), timeout=timeout)
        except httpx.HTTPError as exc:
            raise ProviderError(f"{self.name}: request failed: {exc}") from exc

        if response.status_code >= 400:
            raise ProviderError(f"{self.name}: HTTP {response.status_code}: {response.text[:400]}")

        try:
            data = response.json()
            choice = data["choices"][0]
            text = choice["message"]["content"] or ""
        except (KeyError, IndexError, ValueError) as exc:
            raise ProviderError(f"{self.name}: malformed response: {response.text[:400]}") from exc

        return ChatResult(
            text=text,
            provider=self.name,
            model=data.get("model", self.model),
            finish_reason=choice.get("finish_reason"),
            usage=data.get("usage", {}) or {},
            latency_ms=(time.perf_counter() - started) * 1000.0,
            raw=data,
        )

    def available(self) -> bool:
        # Local servers (LM Studio, vLLM) need no key; hosted ones do.
        if self.base_url.startswith(("http://127.0.0.1", "http://localhost", "http://0.0.0.0")):
            return True
        return bool(self.api_key)

    def list_models(self) -> list[str]:
        try:
            response = httpx.get(f"{self.base_url}/models", headers=self._headers(), timeout=10.0)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError):
            return []
        items = data.get("data", data) if isinstance(data, dict) else data
        out: list[str] = []
        for item in items or []:
            if isinstance(item, dict) and item.get("id"):
                out.append(str(item["id"]))
        return out

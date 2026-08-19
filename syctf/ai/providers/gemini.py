"""Google Gemini (Generative Language API) adapter."""

from __future__ import annotations

import time
from typing import Any

import httpx

from syctf.ai.providers.base import BaseProvider, ChatResult, Message, ProviderError, split_system


class GeminiProvider(BaseProvider):
    """Talks the Gemini ``:generateContent`` wire format over plain HTTP."""

    name = "gemini"

    def __init__(self, *, model: str, base_url: str, api_key: str | None = None) -> None:
        super().__init__(model=model, api_key=api_key, base_url=base_url)

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
        contents = [
            {
                "role": "model" if m.get("role") == "assistant" else "user",
                "parts": [{"text": m.get("content", "")}],
            }
            for m in rest
        ]
        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}

        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key or ''}"
        started = time.perf_counter()
        try:
            response = httpx.post(url, json=payload, timeout=timeout)
        except httpx.HTTPError as exc:
            raise ProviderError(f"gemini: request failed: {exc}") from exc

        if response.status_code >= 400:
            raise ProviderError(f"gemini: HTTP {response.status_code}: {response.text[:400]}")

        try:
            data = response.json()
            candidate = data["candidates"][0]
            parts = candidate["content"]["parts"]
            text = "".join(p.get("text", "") for p in parts)
        except (KeyError, IndexError, ValueError) as exc:
            raise ProviderError(f"gemini: malformed response: {response.text[:400]}") from exc

        return ChatResult(
            text=text,
            provider=self.name,
            model=self.model,
            finish_reason=candidate.get("finishReason"),
            usage=data.get("usageMetadata", {}) or {},
            latency_ms=(time.perf_counter() - started) * 1000.0,
            raw=data,
        )

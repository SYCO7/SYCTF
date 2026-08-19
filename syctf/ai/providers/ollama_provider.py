"""Local Ollama adapter -- reuses SYCTF's existing host resolver."""

from __future__ import annotations

import time
from typing import Any

from syctf.ai.providers.base import BaseProvider, ChatResult, Message, ProviderError


class OllamaProvider(BaseProvider):
    """Runs models locally through the Ollama daemon (no API key)."""

    name = "ollama"

    def __init__(self, *, model: str, base_url: str | None = None, api_key: str | None = None) -> None:
        super().__init__(model=model, api_key=None, base_url=base_url or "")

    def _client(self, timeout: float):
        # Imported lazily so the package loads even without ollama installed.
        from syctf.ai.client import get_ollama_client

        return get_ollama_client(timeout=timeout)

    def chat(
        self,
        messages: list[Message],
        *,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        timeout: float = 120.0,
        **kwargs: Any,
    ) -> ChatResult:
        started = time.perf_counter()
        options = {"temperature": temperature, "num_predict": max_tokens}
        options.update({k: v for k, v in kwargs.items() if v is not None})
        try:
            client = self._client(timeout)
            data = client.chat(model=self.model, messages=messages, options=options)
        except Exception as exc:  # ollama raises many error types
            raise ProviderError(f"ollama: {exc}") from exc

        text = ""
        if isinstance(data, dict):
            text = (data.get("message") or {}).get("content", "")
        else:  # newer ollama returns objects
            message = getattr(data, "message", None)
            text = getattr(message, "content", "") if message is not None else ""

        return ChatResult(
            text=text or "",
            provider=self.name,
            model=self.model,
            finish_reason="stop",
            usage={},
            latency_ms=(time.perf_counter() - started) * 1000.0,
            raw=data if isinstance(data, dict) else None,
        )

    def available(self) -> bool:
        try:
            from syctf.ai.client import get_ai_connection_diagnostics

            return get_ai_connection_diagnostics(model=self.model).connected_host is not None
        except Exception:
            return False

    def list_models(self) -> list[str]:
        try:
            from syctf.ai.client import get_ai_connection_diagnostics

            return list(get_ai_connection_diagnostics(model=self.model).available_models)
        except Exception:
            return []

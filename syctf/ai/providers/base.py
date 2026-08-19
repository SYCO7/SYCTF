"""Provider-agnostic chat abstraction for SYCTF AI backends.

Every concrete backend (OpenAI-compatible, Anthropic, Gemini, Ollama, ...)
implements :class:`BaseProvider` so the router and engine can treat any model
from any vendor through one interface. Messages use the OpenAI shape:
``[{"role": "system|user|assistant", "content": "..."}]``.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

Message = dict[str, str]


class ProviderError(RuntimeError):
    """Raised when a provider call fails (network, auth, quota, bad model)."""


@dataclass(slots=True)
class ChatResult:
    """Normalized result returned by every provider."""

    text: str
    provider: str
    model: str
    finish_reason: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    latency_ms: float | None = None
    raw: dict[str, Any] | None = None

    def __bool__(self) -> bool:
        return bool(self.text.strip())


def split_system(messages: list[Message]) -> tuple[str, list[Message]]:
    """Return (joined system prompt, remaining non-system messages)."""

    system_parts: list[str] = []
    rest: list[Message] = []
    for message in messages:
        if message.get("role") == "system":
            content = str(message.get("content", "")).strip()
            if content:
                system_parts.append(content)
        else:
            rest.append(message)
    return "\n\n".join(system_parts), rest


class BaseProvider(abc.ABC):
    """Common interface for all chat backends."""

    #: Stable provider identifier, e.g. "openai" or "ollama".
    name: str = "base"

    def __init__(self, *, model: str, api_key: str | None = None, base_url: str | None = None) -> None:
        self.model = model
        self.api_key = api_key
        self.base_url = (base_url or "").rstrip("/")

    @abc.abstractmethod
    def chat(
        self,
        messages: list[Message],
        *,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        timeout: float = 60.0,
        **kwargs: Any,
    ) -> ChatResult:
        """Send a chat completion request and return a normalized result."""

    def chat_text(self, prompt: str, *, system: str | None = None, **kwargs: Any) -> str:
        """Convenience: single-turn prompt, return the text only."""

        messages: list[Message] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self.chat(messages, **kwargs).text

    def available(self) -> bool:
        """Best-effort readiness check (key present / host reachable)."""

        return bool(self.api_key)

    def list_models(self) -> list[str]:
        """Best-effort list of model ids; empty when unsupported."""

        return []

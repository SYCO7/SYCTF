"""Model router: pick a provider/model per task tier, with local fallback.

Tiers let the engine spend cheaply where it can and reason strongly where it
must:

* ``route``  -- fast, tiny local model for classification / next-step picking
* ``reason`` -- the main solver brain (local offensive model or a frontier key)
* ``code``   -- code/exploit generation (a coder-tuned model)

Any hosted provider that errors (no key, quota, network) transparently falls
back to the local Ollama model so the toolkit still works offline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from syctf.ai.providers import BaseProvider, ChatResult, Message, ProviderError, build_provider
from syctf.ai.providers.catalog import get_spec
from syctf.ai.settings import AISettings, load_ai_settings

logger = logging.getLogger("syctf.ai.router")


@dataclass(slots=True)
class RouteResult:
    """A completion plus the routing decision that produced it."""

    result: ChatResult
    tier: str
    used_fallback: bool


class ModelRouter:
    """Resolves the right backend for each call and handles fallback."""

    def __init__(self, settings: AISettings | None = None) -> None:
        self.settings = settings or load_ai_settings()

    # -- provider selection -------------------------------------------------
    def _is_local(self, provider_name: str) -> bool:
        try:
            return get_spec(provider_name).local
        except KeyError:
            return False

    def _provider_for(self, tier: str) -> tuple[str, str]:
        provider = self.settings.provider_for(tier)
        model = self.settings.model_for(tier)
        if self.settings.offline_only and not self._is_local(provider):
            logger.info("offline_only set; routing %s -> local fallback", tier)
            return self.settings.fallback_provider, self.settings.fallback_model
        return provider, model

    def _fallback(self) -> BaseProvider:
        return build_provider(self.settings.fallback_provider, model=self.settings.fallback_model)

    # -- completion ---------------------------------------------------------
    def complete(
        self,
        messages: list[Message],
        *,
        tier: str = "reason",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> RouteResult:
        """Run one completion for a tier, falling back to local on failure."""

        provider_name, model = self._provider_for(tier)
        temp = self.settings.temperature if temperature is None else temperature
        tokens = self.settings.max_tokens if max_tokens is None else max_tokens

        try:
            provider = build_provider(provider_name, model=model)
            result = provider.chat(messages, temperature=temp, max_tokens=tokens)
            return RouteResult(result=result, tier=tier, used_fallback=False)
        except ProviderError as exc:
            logger.warning("provider %s failed (%s); using fallback", provider_name, exc)

        fallback = self._fallback()
        result = fallback.chat(messages, temperature=temp, max_tokens=tokens)
        return RouteResult(result=result, tier=tier, used_fallback=True)

    def complete_text(self, prompt: str, *, system: str | None = None, tier: str = "reason") -> str:
        """Convenience single-turn text completion."""

        messages: list[Message] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self.complete(messages, tier=tier).result.text

    # -- self-consistency ---------------------------------------------------
    def ensemble(
        self,
        messages: list[Message],
        *,
        tier: str = "reason",
        n: int | None = None,
        max_tokens: int | None = None,
    ) -> list[ChatResult]:
        """Sample the tier ``n`` times with jittered temperature for voting."""

        samples = max(1, n if n is not None else self.settings.ensemble)
        out: list[ChatResult] = []
        base_temp = self.settings.temperature
        for i in range(samples):
            temp = min(1.0, base_temp + i * 0.25)
            try:
                out.append(self.complete(messages, tier=tier, temperature=temp, max_tokens=max_tokens).result)
            except ProviderError as exc:
                logger.warning("ensemble sample %d failed: %s", i, exc)
        return out

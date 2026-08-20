"""Provider factory: build any backend from its name + environment keys."""

from __future__ import annotations

import os
from dataclasses import dataclass

from syctf.ai.providers.anthropic import AnthropicProvider
from syctf.ai.providers.base import BaseProvider, ChatResult, Message, ProviderError
from syctf.ai.providers.catalog import PROVIDERS, ProviderSpec, get_spec, provider_names
from syctf.ai.providers.gemini import GeminiProvider
from syctf.ai.providers.ollama_provider import OllamaProvider
from syctf.ai.providers.openai_compatible import OpenAICompatibleProvider

__all__ = [
    "BaseProvider",
    "ChatResult",
    "Message",
    "ProviderError",
    "ProviderStatus",
    "build_provider",
    "provider_names",
    "provider_status",
    "resolve_api_key",
]


def resolve_api_key(spec: ProviderSpec) -> str | None:
    """Return the provider's key: env vars first, then the menu keystore."""

    for env_name in spec.env:
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    try:
        from syctf.ai.keystore import get_key

        return get_key(spec.name)
    except Exception:  # noqa: BLE001
        return None


def _resolve_base_url(spec: ProviderSpec) -> str:
    """Allow ``SYCTF_<NAME>_BASE_URL`` to override the default endpoint."""

    override = os.environ.get(f"SYCTF_{spec.name.upper()}_BASE_URL", "").strip()
    return override or spec.base_url


def build_provider(
    name: str,
    *,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> BaseProvider:
    """Construct a ready provider for ``name`` using env keys as fallback."""

    spec = get_spec(name)
    resolved_model = model or spec.model
    resolved_key = api_key or resolve_api_key(spec)
    resolved_base = base_url or _resolve_base_url(spec)

    if spec.kind == "anthropic":
        return AnthropicProvider(model=resolved_model, base_url=resolved_base, api_key=resolved_key)
    if spec.kind == "gemini":
        return GeminiProvider(model=resolved_model, base_url=resolved_base, api_key=resolved_key)
    if spec.kind == "ollama":
        return OllamaProvider(model=resolved_model, base_url=resolved_base)
    return OpenAICompatibleProvider(
        name=spec.name, model=resolved_model, base_url=resolved_base, api_key=resolved_key
    )


@dataclass(slots=True)
class ProviderStatus:
    """Configuration readiness for one provider (no network calls)."""

    name: str
    kind: str
    configured: bool
    local: bool
    default_model: str
    env_hint: str


def provider_status() -> list[ProviderStatus]:
    """Report which providers are configured, for menu diagnostics."""

    rows: list[ProviderStatus] = []
    for spec in PROVIDERS.values():
        key = resolve_api_key(spec)
        rows.append(
            ProviderStatus(
                name=spec.name,
                kind=spec.kind,
                configured=spec.local or bool(key),
                local=spec.local,
                default_model=spec.model,
                env_hint=(spec.env[0] if spec.env else "(none)"),
            )
        )
    return rows

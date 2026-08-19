"""Provider catalog / factory tests (no network)."""

from __future__ import annotations

import pytest

from syctf.ai.providers import build_provider, provider_names, provider_status
from syctf.ai.providers.anthropic import AnthropicProvider
from syctf.ai.providers.base import split_system
from syctf.ai.providers.gemini import GeminiProvider
from syctf.ai.providers.ollama_provider import OllamaProvider
from syctf.ai.providers.openai_compatible import OpenAICompatibleProvider


def test_catalog_has_core_providers():
    names = set(provider_names())
    assert {"ollama", "anthropic", "openai", "gemini", "groq", "nvidia"} <= names
    assert len(names) >= 15


@pytest.mark.parametrize(
    "name,cls",
    [
        ("openai", OpenAICompatibleProvider),
        ("groq", OpenAICompatibleProvider),
        ("nvidia", OpenAICompatibleProvider),
        ("anthropic", AnthropicProvider),
        ("gemini", GeminiProvider),
        ("ollama", OllamaProvider),
    ],
)
def test_build_provider_dispatch(name, cls):
    provider = build_provider(name)
    assert isinstance(provider, cls)
    assert provider.model


def test_unknown_provider_raises():
    with pytest.raises(KeyError):
        build_provider("does-not-exist")


def test_env_key_override(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-123")
    provider = build_provider("openai")
    assert provider.api_key == "sk-test-123"


def test_split_system():
    system, rest = split_system(
        [{"role": "system", "content": "S"}, {"role": "user", "content": "U"}]
    )
    assert system == "S"
    assert rest == [{"role": "user", "content": "U"}]


def test_provider_status_marks_local_configured():
    status = {s.name: s for s in provider_status()}
    assert status["ollama"].configured is True
    assert status["ollama"].local is True

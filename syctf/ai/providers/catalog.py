"""Registry of supported AI providers ("bring any API key").

Each entry describes how to reach a vendor:

* ``kind``     -- wire protocol adapter to use (openai | anthropic | gemini | ollama)
* ``base_url`` -- default REST endpoint (user-overridable via ``*_BASE_URL`` env)
* ``env``      -- environment variable(s) that hold the API key, first match wins
* ``model``    -- sensible default model id
* ``local``    -- True for on-box servers that need no API key
* ``docs``     -- where the user gets a key

Most vendors expose an OpenAI-compatible ``/chat/completions`` surface, so they
all share the ``openai`` adapter. Anthropic and Gemini use their own shapes.
Adding a new OpenAI-compatible vendor is a single dict entry -- no new code.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """Static description of one provider."""

    name: str
    kind: str
    base_url: str
    model: str
    env: tuple[str, ...] = field(default_factory=tuple)
    local: bool = False
    docs: str = ""


# Ordered roughly by how commonly CTF players will reach for them.
PROVIDERS: dict[str, ProviderSpec] = {
    # --- local, no key required -------------------------------------------
    "ollama": ProviderSpec(
        "ollama", "ollama", "http://127.0.0.1:11434", "hf.co/TheBloke/WhiteRabbitNeo-13B-GGUF",
        local=True, docs="https://ollama.com",
    ),
    "lmstudio": ProviderSpec(
        "lmstudio", "openai", "http://127.0.0.1:1234/v1", "local-model",
        env=("LMSTUDIO_API_KEY",), local=True, docs="https://lmstudio.ai",
    ),
    "vllm": ProviderSpec(
        "vllm", "openai", "http://127.0.0.1:8000/v1", "local-model",
        env=("VLLM_API_KEY",), local=True, docs="https://docs.vllm.ai",
    ),
    # --- frontier / hosted ------------------------------------------------
    "anthropic": ProviderSpec(
        "anthropic", "anthropic", "https://api.anthropic.com/v1", "claude-sonnet-4-5",
        env=("ANTHROPIC_API_KEY", "CLAUDE_API_KEY"), docs="https://console.anthropic.com",
    ),
    "openai": ProviderSpec(
        "openai", "openai", "https://api.openai.com/v1", "gpt-4.1",
        env=("OPENAI_API_KEY",), docs="https://platform.openai.com/api-keys",
    ),
    "gemini": ProviderSpec(
        "gemini", "gemini", "https://generativelanguage.googleapis.com/v1beta", "gemini-2.5-flash",
        env=("GEMINI_API_KEY", "GOOGLE_API_KEY"), docs="https://aistudio.google.com/app/apikey",
    ),
    "groq": ProviderSpec(
        "groq", "openai", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile",
        env=("GROQ_API_KEY",), docs="https://console.groq.com/keys",
    ),
    "nvidia": ProviderSpec(
        "nvidia", "openai", "https://integrate.api.nvidia.com/v1", "meta/llama-3.3-70b-instruct",
        env=("NVIDIA_API_KEY", "NVIDIA_NIM_API_KEY"), docs="https://build.nvidia.com",
    ),
    "openrouter": ProviderSpec(
        "openrouter", "openai", "https://openrouter.ai/api/v1", "meta-llama/llama-3.3-70b-instruct",
        env=("OPENROUTER_API_KEY",), docs="https://openrouter.ai/keys",
    ),
    "deepseek": ProviderSpec(
        "deepseek", "openai", "https://api.deepseek.com", "deepseek-chat",
        env=("DEEPSEEK_API_KEY",), docs="https://platform.deepseek.com",
    ),
    "mistral": ProviderSpec(
        "mistral", "openai", "https://api.mistral.ai/v1", "mistral-large-latest",
        env=("MISTRAL_API_KEY",), docs="https://console.mistral.ai",
    ),
    "together": ProviderSpec(
        "together", "openai", "https://api.together.xyz/v1", "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        env=("TOGETHER_API_KEY",), docs="https://api.together.ai",
    ),
    "fireworks": ProviderSpec(
        "fireworks", "openai", "https://api.fireworks.ai/inference/v1",
        "accounts/fireworks/models/llama-v3p3-70b-instruct",
        env=("FIREWORKS_API_KEY",), docs="https://fireworks.ai",
    ),
    "cerebras": ProviderSpec(
        "cerebras", "openai", "https://api.cerebras.ai/v1", "llama-3.3-70b",
        env=("CEREBRAS_API_KEY",), docs="https://cloud.cerebras.ai",
    ),
    "xai": ProviderSpec(
        "xai", "openai", "https://api.x.ai/v1", "grok-4",
        env=("XAI_API_KEY", "GROK_API_KEY"), docs="https://console.x.ai",
    ),
    "perplexity": ProviderSpec(
        "perplexity", "openai", "https://api.perplexity.ai", "sonar-pro",
        env=("PERPLEXITY_API_KEY", "PPLX_API_KEY"), docs="https://docs.perplexity.ai",
    ),
    "sambanova": ProviderSpec(
        "sambanova", "openai", "https://api.sambanova.ai/v1", "Meta-Llama-3.3-70B-Instruct",
        env=("SAMBANOVA_API_KEY",), docs="https://cloud.sambanova.ai",
    ),
}


def get_spec(name: str) -> ProviderSpec:
    """Return the spec for ``name`` or raise KeyError with the valid set."""

    key = name.strip().lower()
    if key not in PROVIDERS:
        valid = ", ".join(sorted(PROVIDERS))
        raise KeyError(f"unknown provider {name!r}; valid: {valid}")
    return PROVIDERS[key]


def provider_names() -> list[str]:
    """Return all known provider names."""

    return sorted(PROVIDERS)

"""AI runtime settings: which provider/model per task tier.

Precedence (high -> low): explicit call args > ``SYCTF_AI_*`` env vars >
``~/.config/syctf/ai.json`` > built-in defaults tuned for an 8-12 GB Kali box.

API keys are NEVER stored here or in the tracked repo config -- they live in
environment variables (see ``.env.example``) or the gitignored ai.json.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any

from syctf.core.paths import get_config_dir

# Local defaults chosen for CPU / small-VRAM Linux boxes (see docs/ai/models).
DEFAULT_LOCAL_REASON = "qwen2.5:7b-instruct-q4_K_M"
DEFAULT_ROUTE_MODEL = "qwen2.5:3b-instruct-q4_K_M"
DEFAULT_CODE_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"

TIERS = ("route", "reason", "code")


@dataclass(slots=True)
class AISettings:
    """Resolved AI configuration for the router."""

    provider: str = "ollama"
    model: str = DEFAULT_LOCAL_REASON
    route_provider: str = ""
    route_model: str = DEFAULT_ROUTE_MODEL
    code_provider: str = ""
    code_model: str = DEFAULT_CODE_MODEL
    fallback_provider: str = "ollama"
    fallback_model: str = DEFAULT_LOCAL_REASON
    temperature: float = 0.2
    max_tokens: int = 2048
    ensemble: int = 1          # >1 enables self-consistency voting
    verify: bool = True        # anti-hallucination gate on/off
    offline_only: bool = False  # ignore hosted providers entirely
    extra: dict[str, Any] = field(default_factory=dict)

    def provider_for(self, tier: str) -> str:
        """Return the provider name to use for a task tier."""

        if tier == "route" and self.route_provider:
            return self.route_provider
        if tier == "code" and self.code_provider:
            return self.code_provider
        return self.provider

    def model_for(self, tier: str) -> str:
        """Return the model id to use for a task tier."""

        if tier == "route":
            return self.route_model or self.model
        if tier == "code":
            return self.code_model or self.model
        return self.model


def _config_path():
    return get_config_dir() / "ai.json"


def _load_file() -> dict[str, Any]:
    path = _config_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def load_ai_settings() -> AISettings:
    """Merge file + environment into a resolved :class:`AISettings`."""

    settings = AISettings()

    # Layer 1: ai.json
    for key, value in _load_file().items():
        if hasattr(settings, key):
            setattr(settings, key, value)

    # Layer 2: environment overrides
    env = os.environ
    settings.provider = env.get("SYCTF_AI_PROVIDER", settings.provider).strip() or settings.provider
    settings.model = env.get("SYCTF_AI_MODEL", settings.model).strip() or settings.model
    settings.route_provider = env.get("SYCTF_AI_ROUTE_PROVIDER", settings.route_provider).strip()
    settings.route_model = env.get("SYCTF_AI_ROUTE_MODEL", settings.route_model).strip() or settings.route_model
    settings.code_provider = env.get("SYCTF_AI_CODE_PROVIDER", settings.code_provider).strip()
    settings.code_model = env.get("SYCTF_AI_CODE_MODEL", settings.code_model).strip() or settings.code_model
    settings.fallback_provider = (
        env.get("SYCTF_AI_FALLBACK_PROVIDER", settings.fallback_provider).strip() or "ollama"
    )
    settings.fallback_model = (
        env.get("SYCTF_AI_FALLBACK_MODEL", settings.fallback_model).strip() or settings.fallback_model
    )
    if "SYCTF_AI_TEMPERATURE" in env:
        try:
            settings.temperature = float(env["SYCTF_AI_TEMPERATURE"])
        except ValueError:
            pass
    if "SYCTF_AI_ENSEMBLE" in env:
        try:
            settings.ensemble = max(1, int(env["SYCTF_AI_ENSEMBLE"]))
        except ValueError:
            pass
    settings.verify = _bool_env("SYCTF_AI_VERIFY", settings.verify)
    settings.offline_only = _bool_env("SYCTF_AI_OFFLINE", settings.offline_only)
    return settings


def save_ai_settings(settings: AISettings) -> None:
    """Persist non-secret settings to ai.json (never writes API keys)."""

    path = _config_path()
    data = {k: v for k, v in asdict(settings).items() if k != "extra"}
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

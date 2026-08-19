# Changelog

All notable changes to SYCTF are documented here.

## [0.2.0] — "Hydra"

Autonomous, provider-agnostic release.

### Added
- **Autonomous solve engine** (`syctf/engine`): ingest a file/dir/text/URL/host,
  run grounded deterministic collectors, plan per category, reason with AI, and
  return a verified flag. New `syctf solve <target>` command (CLI + shell menu).
- **Multi-provider AI layer** (`syctf/ai/providers`): one interface over 17
  backends — Ollama, Anthropic, OpenAI, Gemini, Groq, NVIDIA NIM, OpenRouter,
  DeepSeek, Mistral, Together, Fireworks, Cerebras, xAI, Perplexity, SambaNova,
  LM Studio, vLLM. Pure-HTTP (no vendor SDKs). `syctf ai providers` diagnostics.
- **Model router** (`syctf/ai/router`): per-tier model selection (route/reason/
  code) with automatic local fallback and self-consistency ensembling.
- **Anti-hallucination verifier** (`syctf/ai/verifier`): flag grounding,
  self-consistency voting, confidence gating, and a learning log of caught
  mistakes fed back as negative examples.
- **Flag engine** (`syctf/flags`): pattern detection over text/bytes, custom
  formats, and placeholder rejection.
- Settings via env / gitignored `~/.config/syctf/ai.json` — keys never in-repo.
- CI workflow, unit tests for flags/verifier/providers/engine.
- `docs/ai/models.md`: best local model guide for 8–12 GB Kali.

### Changed
- `ollama` is now imported lazily — SYCTF runs on a hosted key alone.
- README rewritten to match shipped capabilities; added a differentiation
  section vs. other AI CTF tools.
- `httpx` promoted to a core dependency.

# SYCTF AI — model selection guide

SYCTF runs any model from any provider. This page is the **practical pick** for
the common Kali setup: a laptop with **16–32 GB total RAM**, of which **8–12 GB
is given to the Kali VM**, usually **CPU-only** (no GPU passthrough).

Under CPU inference, RAM (not VRAM) is the limit and a 4-bit 7–8B model is the
sweet spot: ~5 GB resident, usable tokens/sec, and strong enough to reason about
CTF evidence when grounded by SYCTF's collectors.

## ⭐ The pick for a Kali 8 GB VM (CPU): `qwen2.5:7b-instruct-q4_K_M`

```bash
ollama pull qwen2.5:7b-instruct-q4_K_M      # ~4.7 GB
# if the VM is tight / stutters, drop to the 3B — still smooth, still solid:
ollama pull qwen2.5:3b-instruct-q4_K_M      # ~2.2 GB
```
Why this over the alternatives, for *this* job (SYCTF's agent = pick a tool →
read evidence → answer, with anti-hallucination):

- **Best instruction-following + tool use at 7B** — the agent emits JSON tool
  calls; Qwen2.5 follows that reliably. Fast on CPU, fits 8 GB with headroom.
- **Well-calibrated (low hallucination)** — it will say "unknown" instead of
  inventing, which is exactly what you want; SYCTF's grounding does the rest.
- **Reliable, official ollama tags** — no broken HuggingFace pulls.

### Why **not** WhiteRabbitNeo / DeepHat as the default here
It's a great *offensive-writing* model, but a poor fit for an 8 GB Kali VM CTF
solver:

- **Too big** — the 13B eats ~8–10 GB (Q4), i.e. your whole VM → swapping and
  stalls; even the 7B leaves little room for Kali + tools.
- **Tuned for generation, not tool-following/reasoning** — it writes exploits
  and explanations well, but is weaker at the structured JSON tool-calls and
  step reasoning SYCTF's agent needs.
- **More prone to hallucinate** — uncensored "always answer" tuning fabricates
  more; you asked for *no* hallucination.
- **Flaky tags** — community GGUF repos move/deprecate; pulls fail.

Use WhiteRabbitNeo/DeepHat only when you specifically need uncensored exploit
*generation* and have the RAM — not as the everyday solver brain.

### VM tuning for smoothness
- Give the VM the **full 8 GB** (more if the host allows) and keep Kali lean.
- Use **Q4_K_M** quants; add a few GB of swap as a safety net.
- One request at a time: `export OLLAMA_NUM_PARALLEL=1` and a modest context
  `export OLLAMA_CONTEXT_LENGTH=4096`.
- `syctf ai-setup` reads your RAM and recommends the right size automatically.

## Recommended local stack (Ollama, Linux)

| Tier | Model | Pull | Size (Q4) | Why |
|---|---|---|---|---|
| **reason** (default) | `qwen2.5:7b-instruct-q4_K_M` | `ollama pull qwen2.5:7b-instruct-q4_K_M` | ~4.7 GB | Fast, reliable 7B; fits 8 GB |
| **reason** (best for CTF) | `deepseek-r1:7b` | `ollama pull deepseek-r1:7b` | ~4.7 GB | R1 reasoning distill — chain-of-thought for crypto/logic |
| **reason** (offensive) | DeepHat / WhiteRabbitNeo 7–13B GGUF | via Ollama Modelfile | 5–8 GB | Cyber-tuned, won't refuse exploit/payload work |
| **reason** (accuracy) | Foundation-Sec-8B (Llama-3.1 cyber CPT) | GGUF import | ~5 GB | ~GPT-4o-mini on threat-intel tasks |
| **route** (triage) | `qwen2.5:3b-instruct-q4_K_M` | `ollama pull qwen2.5:3b-instruct-q4_K_M` | ~2.2 GB | Fast category/next-step picking |
| **code** (exploit) | `qwen2.5-coder:7b-instruct-q4_K_M` | `ollama pull qwen2.5-coder:7b-instruct-q4_K_M` | ~4.7 GB | Strong at exploit/script generation |

**8 GB Kali:** run the 3B router + one 7B reasoner (not both 7B loaded at once).
**12 GB Kali:** you can keep a 7B reasoner + 3B router resident comfortably.
**≤6 GB:** use `qwen2.5:3b` for everything, or offload to a free hosted key.

### Cyber-tuned / offensive models
- **DeepHat (formerly WhiteRabbitNeo)** — trained for offensive-sec workflows;
  it answers exploit, payload, and recon prompts other models refuse.
- **Foundation-Sec-8B** — continued-pretrained on a curated cyber corpus;
  state-of-the-art for its size on threat-intel benchmarks.

Import a GGUF into Ollama with a Modelfile:

```
# Modelfile
FROM ./deephat-7b.Q4_K_M.gguf
PARAMETER temperature 0.2
```
```bash
ollama create deephat -f Modelfile
SYCTF_AI_MODEL=deephat syctf solve ./challenge
```

## Best models for CTF (hosted) — reasoning wins

CTF challenges reward **reasoning** models (chain-of-thought over crypto/pwn/
logic). These are the current strongest picks; SYCTF defaults to them per
provider, and does all the tool-grounding + anti-hallucination around them.

| Tier | Model | Provider (`SYCTF_AI_PROVIDER` → default model) |
|---|---|---|
| 🥇 Top reasoning | **DeepSeek-R1** | `deepseek` (deepseek-reasoner), `together`, `fireworks`, `openrouter` |
| 🥇 Top reasoning | **Nemotron Ultra 253B** | `nvidia` (nvidia/llama-3.1-nemotron-ultra-253b-v1) |
| ⚡ Fast reasoning (free tier) | **R1-distill-70B** | `groq` (deepseek-r1-distill-llama-70b) |
| 🧠 Frontier | **Claude / GPT** | `anthropic` (claude-sonnet-4-5), `openai` (gpt-4.1) |

```bash
# DeepSeek-R1 (best open reasoning)
export DEEPSEEK_API_KEY=sk-...   ; SYCTF_AI_PROVIDER=deepseek syctf agent ./chal
# NVIDIA NIM — Nemotron Ultra (or the lighter Super 49B)
export NVIDIA_API_KEY=nvapi-...  ; SYCTF_AI_PROVIDER=nvidia syctf agent ./chal
SYCTF_AI_MODEL=nvidia/llama-3.3-nemotron-super-49b-v1 syctf agent ./chal   # lighter/faster
# Groq — R1 distill, very fast, generous free tier
export GROQ_API_KEY=gsk_...      ; SYCTF_AI_PROVIDER=groq syctf agent ./chal
```

Nemotron **Ultra 253B** (dense, quality) meets/beats DeepSeek-R1; **Super 49B**
(sparse MoE) trades a little quality for much higher throughput — pick Ultra for
the hardest challenges, Super for speed.

## Anti-hallucination knobs

- `SYCTF_AI_ENSEMBLE=3` — sample the reasoner 3× and vote (self-consistency).
  Disagreement ⇒ SYCTF abstains instead of asserting a wrong answer.
- `SYCTF_AI_VERIFY=1` — a model-claimed flag is accepted **only** if it is not a
  template and literally appears in real tool/file evidence. Ungrounded flags
  are rejected and logged to `~/.syctf/cache/hallucinations.jsonl`, which is fed
  back as negative examples on later runs (the "learn from it" loop).
- `SYCTF_AI_OFFLINE=1` — never leave the box; local models only.

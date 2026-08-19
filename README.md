# SYCTF — Autonomous, Menu-Driven CTF Framework · v0.2.0 “Hydra”

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-2ea44f)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Alpha-f59f00)](https://github.com/SYCO7/SYCTF)
[![CI](https://github.com/SYCO7/SYCTF/actions/workflows/ci.yml/badge.svg)](https://github.com/SYCO7/SYCTF/actions/workflows/ci.yml)
[![AI](https://img.shields.io/badge/AI-Any%20Provider%20%7C%20Local%20First-111827)](docs/ai/models.md)

Terminal-first, **menu-driven** CTF framework for operators who need speed,
repeatability, and an **autonomous solver** that stays honest.

SYCTF pairs deterministic, evidence-grounded automation with an AI layer that
runs on **any provider** (local Ollama or any hosted key) and refuses to guess:
a claimed flag is accepted only when it is verified against real evidence.

---

## 1) 🚀 What Is SYCTF

SYCTF is an offensive security workflow framework focused on:

- CTF workflow automation
- multilayer decoding assistance
- exploit acceleration
- modular security tooling
- optional local AI via Ollama

---

## 2) ✨ Features

| Capability | What You Get |
|---|---|
| **Autonomous Solver** (`syctf solve`) | Point it at a file/dir/text/URL/host — it ingests, runs a grounded deterministic pass, reasons with AI, and returns a **verified** flag |
| **Multi-Provider AI** | 17 backends behind one interface: Ollama (local), Anthropic, OpenAI, Gemini, Groq, NVIDIA NIM, OpenRouter, DeepSeek, Mistral, Together, Fireworks, Cerebras, xAI, Perplexity, SambaNova, LM Studio, vLLM. Bring any key; local fallback is automatic |
| **Anti-Hallucination** | Flag grounding + self-consistency voting + confidence gating; caught mistakes are logged and fed back as negative examples |
| Interactive Offensive Shell | Fast module discovery, command history, context-aware workflow |
| Smart Decode Engine | Multi-layer transforms: base64/base32, hex, reverse, ROT/Caesar, bit-strings |
| Modular Plugin Architecture | Category-driven modules and extensible plugin system |
| Exploit Workflow Acceleration | ELF triage helpers, exploit skeleton generation, workspace context |
| Clean Terminal UX | Rich panels, ranked candidates, pipeline visualization |

---

## 3) 🛠️ Installation (Linux / Kali)

### Step-by-step

```bash
git clone https://github.com/SYCO7/SYCTF.git
cd SYCTF
python3 -m venv ctfvenv
source ctfvenv/bin/activate
pip install -r requirements.txt
python -m syctf
```

### Notes

- The command above starts SYCTF using the package entrypoint.
- If your local branch includes a launcher file, this may also work:

```bash
python syctf.py
```

---

## 4) 🤖 AI Modes — Bring Any Provider

SYCTF runs on **any model from any provider** through one interface. Local by
default (no cloud, air-gap friendly); switch to a hosted key for hard challenges.

```bash
syctf ai providers          # see every backend and which keys are configured
```

### Local (default, no key)

```bash
ollama pull qwen2.5:7b-instruct-q4_K_M
ollama serve
syctf ai-setup
```

### Any hosted key (example: Claude, then NVIDIA, then Groq)

```bash
export ANTHROPIC_API_KEY=sk-...
SYCTF_AI_PROVIDER=anthropic SYCTF_AI_MODEL=claude-sonnet-4-5 syctf solve ./chal

export NVIDIA_API_KEY=nvapi-...
SYCTF_AI_PROVIDER=nvidia syctf solve ./chal

export GROQ_API_KEY=gsk_...
SYCTF_AI_PROVIDER=groq syctf solve ./chal
```

Supported today: **ollama, anthropic, openai, gemini, groq, nvidia, openrouter,
deepseek, mistral, together, fireworks, cerebras, xai, perplexity, sambanova,
lmstudio, vllm**. Any hosted call that fails falls back to your local model.
See [`.env.example`](.env.example) for every key, and
[`docs/ai/models.md`](docs/ai/models.md) for the best local model on an
8–12 GB Kali box.

---

## 4b) 🎯 Autonomous Solve

```bash
syctf solve ./challenge.bin           # file
syctf solve ./chal_dir                # directory
syctf solve "ZmxhZ3toaX0="            # raw ciphertext
syctf solve https://ctf.example/web   # url
syctf solve 10.10.10.5:1337           # host:port

syctf solve ./chal --flag-format "picoCTF{}" --ensemble 3   # custom fmt + voting
syctf solve ./chal --no-ai                                  # deterministic only
```

Pipeline: **ingest → identify → grounded collectors (strings/entropy/hashes/
decode) → category playbook → verified AI reasoning → flag**. Available in the
menu too: type `solve <target>` inside `syctf shell`.

### 🛡️ Anti-hallucination (why the flag is trustworthy)

1. **Flag grounding** — an AI-claimed flag is accepted only if it is not a
   template *and* literally appears in real tool/file evidence.
2. **Self-consistency** — `--ensemble N` samples the model N times and votes;
   disagreement ⇒ SYCTF abstains instead of asserting.
3. **Confidence gating** — low agreement is reported, not hidden.
4. **Learning loop** — rejected flags are logged to
   `~/.syctf/cache/hallucinations.jsonl` and fed back as negative examples.

---

## 4c) 🤖 Autonomous Agent (the crazy one)

Where `solve` runs safe built-in collectors, **`agent`** lets the LLM drive the
*real* SYCTF modules as tools — it plans, runs `rsa-attacks` / `rop-finder` /
`jwt-tool` / `sqli-probe` / `osint` / `mobile` / `cloud`, reads each tool's
actual output, and loops until it captures a **verified** flag.

```bash
syctf agent ./challenge.bin
syctf agent https://ctf.example/login --goal "find SQLi and dump the flag"
syctf agent token.jwt --budget 15
```

- The model emits one JSON action per step (`{"tool": "...", "args": {...}}`),
  SYCTF executes the module, and feeds the real output back as evidence.
- Every claimed flag is grounded against tool output — invented flags are
  rejected, so the agent cannot "win" by hallucinating.
- Needs a reachable AI backend (local Ollama or any hosted key). Available in
  the shell too: `agent <target>`.

---

## 5) ⚡ Quick Start Usage

```bash
syctf shell
list
misc smart-decode <cipher>
ai decode <cipher>
```

You can also run the new direct decode command without entering shell:

```bash
syctf auto-decode <cipher> --script
```

---

## 6) 🧠 Hybrid Mode (Heuristic First, AI Second)

SYCTF decode logic is intentionally staged:

1. Heuristic decoding attempts
2. Transform scoring and ranking
3. Flag pattern detection
4. Optional local AI reasoning only when confidence is low

### Decode strategy includes

- base64 single and multi-layer attempts
- hex decoding
- reverse transforms
- Caesar/ROT brute forcing
- prefix checks: picoCTF{...}, flag{...}, HTB{...}

### Alpha honesty

> AI reasoning may be inconsistent in alpha.
> Use AI output as an accelerator, not as ground truth.

---

## 7) 🖥️ Example Terminal Workflow

```text
$ syctf shell

SYCTF > list
SYCTF > use misc/smart-decode
SYCTF (smart-decode) > run cGljb0NURnt0ZXN0X2ZsYWd9

[Detected Cipher Hints]
- base64-like alphabet detected
- alphabetic payload; Caesar/ROT candidates enabled

[Transform Pipeline Ranking]
1  input -> base64                      score=0.7744  preview=picoCTF{test_flag}
2  input -> base64 -> reverse           score=0.4444  preview=}galf_tset{FTCocip

[Best Candidate]
Pipeline: input -> base64
Output: picoCTF{test_flag}

SYCTF > ai decode cGljb0NURnt0ZXN0X2ZsYWd9
SYCTF > ai exploit ./binary/chall --remote host:31337
```

---

## 8) 🧩 Architecture Overview

- Core shell: command routing, category execution, session state
- Modules: recon, web, pwn, crypto, rev, misc, ai
- Solve engine (`syctf/engine`): ingest → collectors → planner → reasoner → verified flag
- Flag engine (`syctf/flags`): pattern detection + placeholder/grounding checks
- AI layer (`syctf/ai`): provider router (17 backends) + anti-hallucination verifier
- Decode engine: transform-chain exploration + candidate ranking

---

## 9) 🧭 How SYCTF Is Different

Most AI CTF/pentest agents (PentestGPT, EnIGMA, CAI, HackSynth, model-racing
solvers) are **cloud-LLM, single-vendor, and trust the model's answer**. SYCTF
takes the opposite bets:

- **Menu-driven & terminal-first** — no notebook, no web app; works over SSH.
- **Local-first, provider-agnostic** — runs fully offline on a 7–8B model, or
  on *any* hosted key. Not locked to one vendor.
- **Grounded, then reasoned** — deterministic collectors extract real evidence
  before a single token is spent; the model interprets evidence, it doesn't
  invent it.
- **Honest by construction** — a flag must be verified against evidence or it is
  rejected and logged. Anti-hallucination is a feature, not a disclaimer.
- **Air-gap mode** — `SYCTF_AI_OFFLINE=1` guarantees nothing leaves the box.

## 10) 🗺️ Roadmap

**Shipped in 0.2 “Hydra”:** multi-provider AI, autonomous `solve`, flag engine,
anti-hallucination + learning loop, CI.

**Next:**
- deeper category analyzers: crypto (RSA/XOR), pwn (ROP/fmt-string), forensics
- new domains: **mobile** (APK/jadx/MobSF), **cloud** (IAM/SSRF/metadata)
- **OSINT** module wired to recon/subdomain/breach tooling
- exploit scripting with deeper binary context
- shared solve memory across challenges

---

## 11) ⚠️ Disclaimer

SYCTF is for educational use, CTF competitions, and authorized security research.

Do not use this framework on systems you do not own or explicitly have permission to test.

---

## 12) 👤 Author

**Tanmoy Mondal**

- GitHub: [https://github.com/SYCO7](https://github.com/SYCO7)
- LinkedIn: [https://www.linkedin.com/in/tanmoy-mondal-11070334b/](https://www.linkedin.com/in/tanmoy-mondal-11070334b/)
- Portfolio: [https://cybersyco.vercel.app/](https://cybersyco.vercel.app/)

---

### Final Notes

SYCTF is in active alpha.

- Expect rapid changes.
- Expect edge cases in hybrid AI mode.
- Expect practical value today for serious CTF operators.
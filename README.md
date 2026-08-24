<div align="center">

<img src="assets/banner.png" alt="SYCTF — autonomous, menu-driven, local-first CTF framework" width="100%">

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-2ea44f)](LICENSE)
[![CI](https://github.com/SYCO7/SYCTF/actions/workflows/ci.yml/badge.svg)](https://github.com/SYCO7/SYCTF/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SYCO7/SYCTF/actions/workflows/codeql.yml/badge.svg)](https://github.com/SYCO7/SYCTF/actions/workflows/codeql.yml)
[![AI](https://img.shields.io/badge/AI-17%20providers%20·%20bring%20any%20key-111827)](docs/ai/models.md)
[![Release](https://img.shields.io/badge/v2.0.1-%E2%80%9CHydra%E2%80%9D-bc8cff)](CHANGELOG.md)

![SYCTF demo](assets/demo.gif)

</div>

---

## ⚡ Install (Linux / Kali)

```bash
git clone https://github.com/SYCO7/SYCTF.git && cd SYCTF
python3 -m venv ctfvenv && source ctfvenv/bin/activate
pip install -r requirements.txt
pip install .                 # installs the `syctf` command on your PATH
syctf                         # launch the menu   (no install? use: python -m syctf)
```

<b>Windows</b> (Windows Terminal / PowerShell) works too — same steps, different venv path:

```powershell
git clone https://github.com/SYCO7/SYCTF.git; cd SYCTF
python -m venv ctfvenv; .\ctfvenv\Scripts\Activate.ps1
pip install -r requirements.txt; pip install .
syctf
```

<sub><b>Troubleshooting</b> — Kali <code>externally-managed-environment</code>: you're not inside a venv; run the <code>python3 -m venv</code> + <code>source</code> lines first. A leftover <code>ctfvenv</code> from another OS (has <code>Scripts/</code> or a <code>C:\</code> path) is broken on Linux → <code>rm -rf ctfvenv</code> and recreate. Typing <code>syctf</code> does nothing → you skipped <code>pip install .</code> (use <code>python -m syctf</code> meanwhile).</sub>

Docker: `docker build -t syctf . && docker run --rm -it syctf`

---

## ▶ Use it — just pick a number

Run `syctf` (no arguments) and the menu opens:

<div align="center">
<img src="assets/menu.png" alt="SYCTF main menu" width="72%">
</div>

You set the **flag format** once at the start of a challenge (menu → *Set Flag
Format*, or `--flag-format picoCTF{}`) and every module uses it.

Pick a category → pick a module → it prompts for each argument → runs. Everything is also a direct command:

```bash
syctf solve "ZmxhZ3toaX0="                 # autonomous solve (auto-detects type)
syctf agent ./chal --goal "get the flag"   # AI drives real modules to the flag
syctf arena ./ctf_folder --flag-format picoCTF{}   # batch-solve a whole event → scoreboard
syctf crypto-helper rsa-attacks --n 0x.. --e 65537 --c 0x..
syctf forensics stegano --file cat.png
```

```bash
syctf memory                               # techniques SYCTF learned across challenges
python scripts/benchmark.py                # solve-rate over the bundled samples
```

Full walkthrough with ready-made sample challenges → [`docs/DEMO.md`](docs/DEMO.md).

**Learns as you go:** every solved challenge is remembered (category → winning
technique, never the flag) in a local sqlite store and fed back as a hint on
similar challenges. **Benchmark:** `python scripts/benchmark.py` scores the
bundled samples (5/9 with the *deterministic* engine alone — no AI, no category
modules; higher with `--ai` or the per-category tools).

---

## 🧠 How it works

```mermaid
flowchart LR
  T[🎯 target] --> I[ingest + identify]
  I --> C[grounded tools<br/>strings · decode · rsa · rop · stego …]
  C --> R[AI reasons over<br/>real evidence]
  R --> V{flag proven<br/>in evidence?}
  V -- yes --> F[✅ verified flag]
  V -- no --> C
```

- **Grounded first** — deterministic tools extract real evidence *before* any token is spent.
- **Any AI** — local Ollama by default, or Claude / OpenAI / Gemini / Groq / NVIDIA … bring a key, local fallback is automatic.
- **Honest by design** — a flag is accepted only if it literally appears in tool output (never guessed). **Planted decoys** (`fake`, `try_harder`, `not_the_real…`) are recognised and skipped, so SYCTF keeps looking for the real one. Absolute certainty? point it at an oracle — a published hash or a checker — via `verify_flag`.
- **`agent` mode** — the LLM picks and runs the *actual* SYCTF modules in a loop, not just built-ins.

> **vs. other AI solvers** (PentestGPT · EnIGMA · CAI …): those are cloud-LLM,
> single-vendor, and trust the model's answer. SYCTF is **local-first**,
> **any-provider**, **menu-driven**, and **won't report a flag it can't prove** —
> decoys and hallucinations are rejected, not submitted.

---

## 🧩 What's inside

| | Tools |
|---|---|
| **Crypto** | RSA attacks (factordb/Fermat/Wiener/low-exp) + PEM decrypt, XOR, decode, hashes |
| **Pwn** | ROP gadget finder, heap helper (libc offsets / bin math), format-string writes, ELF triage, offsets |
| **Web** | SQLi, XSS, LFI, JWT (alg=none / crack) |
| **Forensics** | LSB & WAV-audio stego, git forensics (dangling commits), EXIF/metadata (+ key recovery), pcap, zip-crack |
| **Mobile** | APK manifest (AXML), hardcoded secrets, DEX strings |
| **Cloud** | S3 enum, IMDS-SSRF, cloud-key scan |
| **OSINT** | subdomains, DNS, RDAP whois, wayback, username-enum |
| **Core** | recon · fuzz · rev · misc · Arena · solve-memory · 17-provider AI · plugins |

46 tools across 13 categories, all reachable from the menu. Self-contained:
pure-Python (even the PNG decoder, binary-AXML parser, and RSA/ROP tooling) — no
heavy external tools required. CodeQL + Bandit + dependency scanning on every push.

---

## 🔌 Bring any AI

Set a key **from the menu** — *AI & Providers → Set AI Key* → pick a provider,
paste the key (hidden), it saves & activates it (stored in `~/.config/syctf/`,
never in the repo). No shell exports needed. Or do it by hand:

```bash
export NVIDIA_API_KEY=nvapi-...
SYCTF_AI_PROVIDER=nvidia syctf agent ./chal      # NVIDIA Nemotron (or claude/openai/gemini/groq/…)
```

`syctf ai providers` lists all 17 backends and what's configured. Best local models for an 8–12 GB Kali box → [`docs/ai/models.md`](docs/ai/models.md).

**Hardware-aware:** `syctf ai-setup` detects your OS, RAM, CPU, and **NVIDIA GPU/VRAM** (Windows & Linux) and recommends the best local model for *your* box — a bigger reasoning model when you have a real GPU (e.g. 24 GB VRAM → a 32B), a lean one on a small CPU-only VM (8 GB → a 7B), and points you at a hosted key when local can't keep up.

---

## 👤 Author

**Tanmoy Mondal**
[GitHub](https://github.com/SYCO7) · [LinkedIn](https://www.linkedin.com/in/tanmoy-mondal-11070334b/) · [Portfolio](https://cybersyco.vercel.app/)

<sub>MIT licensed · for CTFs, education, and authorized security research only.</sub>

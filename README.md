# SYCTF - Offensive Security Terminal Framework

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-2ea44f)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Alpha-f59f00)](https://github.com/SYCO7/SYCTF)
[![Local AI](https://img.shields.io/badge/AI-Ollama%20Local-111827?logo=ollama)](https://ollama.com)

Terminal-first offensive security framework for CTF operators who need speed, repeatability, and modular workflows.

SYCTF blends deterministic automation with optional local AI reasoning for decoding, triage, and exploit acceleration.

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
| Interactive Offensive Shell | Fast module discovery, command history, context-aware workflow |
| Smart Decode Engine | Multi-layer transforms: base64, hex, reverse, Caesar/ROT search |
| Hybrid AI Mode | Heuristic-first decoding + optional local LLM reasoning |
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

## 4) 🤖 Optional AI Mode Setup (Ollama)

SYCTF can run with local AI assistance. No cloud dependency required.

### Install and start Ollama

```bash
ollama pull deepseek-coder:6.7b
ollama serve
```

### Verify SYCTF AI integration

```bash
syctf ai-setup
```

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
- Decode engine: transform-chain exploration + candidate ranking
- AI connector: local Ollama client + model diagnostics
- Scoring system: readability, braces, known-prefix matches, entropy reduction

---

## 9) 🗺️ Roadmap

- auto exploit scripting with deeper binary context
- stronger cipher and encoding recognition
- plugin marketplace expansion and trust controls
- remote collaboration mode for team operations

---

## 10) ⚠️ Disclaimer

SYCTF is for educational use, CTF competitions, and authorized security research.

Do not use this framework on systems you do not own or explicitly have permission to test.

---

## 11) 👤 Author

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
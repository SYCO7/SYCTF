# SYCTF | AI-Native CTF Automation Framework

![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

SYCTF is a terminal-first CTF automation framework for players who want speed, structure, and local AI assistance without surrendering control.

It combines:
- deterministic security tooling (recon, pwn, crypto, rev, web)
- reproducible challenge workspaces
- local Ollama-powered AI for exploit and writeup acceleration
- plugin-based extensibility for team workflows

Professional enough for repeatable team ops, fast enough for live CTF pressure.

## Table of Contents

- [Why SYCTF](#why-syctf)
- [Core Features](#core-features)
- [Hybrid AI Architecture](#hybrid-ai-architecture)
- [Architecture Diagram](#architecture-diagram)
- [Recommended Setup](#recommended-setup)
- [Installation](#installation)
  - [Windows PowerShell](#windows-powershell)
  - [Kali Linux](#kali-linux)
  - [Optional pwn dependencies](#optional-pwn-dependencies)
- [Quick Start](#quick-start)
- [Step-by-Step Usage](#step-by-step-usage)
- [Real CTF Workflow Examples](#real-ctf-workflow-examples)
- [Plugin System](#plugin-system)
- [AI Mode](#ai-mode)
- [Demo](#demo)
- [Performance Tips](#performance-tips)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

## Why SYCTF

Most CTF time is lost in context-switching and repeated glue code.

SYCTF solves that by giving you one command surface for:
- environment checks
- smart decoding
- web triage and fuzzing
- pwn analysis and exploit skeleton generation
- writeup generation from session artifacts

You keep manual control. SYCTF removes repetitive friction.

## Core Features

- 🧠 Recursive smart decoder with layered heuristics
- 🧩 ELF triage with exploitability hints
- ⚙️ AI exploit skeleton generation (local Ollama)
- 📝 AI writeup generation with safe fallback mode
- 🌐 Web recon helpers (quick recon, dir brute, param fuzz)
- 🗂 Workspace scaffolding with persistent state
- 🔌 Plugin marketplace and dynamic module loading
- 💻 Interactive shell with AI mode and command history

## Hybrid AI Architecture

SYCTF supports a practical hybrid mode used by many players:
- Ollama runs on host machine (Windows/Linux desktop)
- SYCTF runs inside Kali VM
- Kali connects to host Ollama via OLLAMA_HOST

This gives you:
- better model performance on host hardware
- clean offensive tooling workflow inside Kali
- local/offline inference path for sensitive challenge data

### Hybrid Mode Setup (Host Ollama + Kali SYCTF)

1. Start Ollama on host.
2. Get host IP reachable from Kali VM.
3. Set OLLAMA_HOST in Kali to host IP:11434.
4. Verify connectivity from Kali.
5. Run SYCTF AI commands from Kali.

Kali example:

```bash
export OLLAMA_HOST=http://192.168.56.1:11434
curl http://192.168.56.1:11434/api/tags
syctf ai-setup
```

PowerShell host example:

```powershell
# Start Ollama in another terminal if not already running
ollama serve
ollama pull deepseek-coder:6.7b
```

## Architecture Diagram

```text
                         +---------------------------+
                         |      Host Machine         |
                         |  (Windows / Linux Desktop)|
                         |                           |
                         |  Ollama Server            |
                         |  :11434                   |
                         +-------------+-------------+
                                       |
                      HTTP (OLLAMA_HOST)|
                                       v
+---------------------------------------------------------+
|                    Kali VM (Operator Box)               |
|                                                         |
|  +--------------------+    +--------------------------+ |
|  |   SYCTF CLI/Shell  |--->|  Module System           | |
|  |                    |    |  recon/crypto/pwn/web... | |
|  +---------+----------+    +-------------+------------+ |
|            |                               |            |
|            v                               v            |
|  +--------------------+         +---------------------+ |
|  | Workspace Engine   |         | AI Session Layer    | |
|  | binary/exploit/... |         | exploit/writeup/chat| |
|  +--------------------+         +---------------------+ |
|                                                         |
+---------------------------------------------------------+
```

## Recommended Setup

Use this baseline for smooth operation:

- Python: 3.10 or 3.11
- RAM: 16 GB+ preferred for deepseek-coder:6.7b
- Disk: SSD for faster venv/model operations
- Kali VM networking: Bridged or Host-Only (stable host IP)
- Ollama models:
  - low RAM: phi
  - medium: deepseek-coder:6.7b
  - high RAM/GPU: codellama:13b

## Installation

### Windows PowerShell

```powershell
git clone https://github.com/SYCO7/SYCTF.git
cd SYCTF

py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install .

# verify
syctf --help
```

If script execution is blocked:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Kali Linux

```bash
git clone https://github.com/SYCO7/SYCTF.git
cd SYCTF

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
pip install .

# verify
syctf --help
```

### Optional pwn dependencies

Pwntools is optional and not installed in base dependencies.

For full pwn workflow (recommended on Kali/Linux):

```bash
pip install 'syctf[pwn]'
```

Windows note:
- SYCTF runs on Windows, but advanced pwn flows may be limited.
- You will see a limited-mode notice for pwn commands.
- Best practice: run pwn modules in Kali/Linux.

## Quick Start

```bash
# 1) Verify install
syctf --help

# 2) Run AI setup check
syctf ai-setup

# 3) Start interactive shell
syctf shell
```

Direct command mode (no shell):

```bash
syctf misc smart-decode SGVsbG8=
syctf recon http-headers --url https://example.com
```

If syctf is not in PATH yet:

```bash
python -m syctf shell
```

## Step-by-Step Usage

### 1) Create workspace

```bash
syctf workspace init babyrop
```

Creates:
- binary/
- exploit/
- decoded/
- notes/
- scripts/

### 2) Set target binary

```bash
syctf workspace set-target ./binary/chall
```

### 3) Run triage and decode helpers

```bash
syctf pwn-helper elf-analyze ./binary/chall
syctf misc smart-decode 'U0dWc2JHOD0='
syctf crypto-helper hash-ident --hash 5d41402abc4b2a76b9719d911017c592
```

### 4) Run web checks

```bash
syctf web-helper quick-recon https://target.ctf
syctf web-helper dir-bruteforce --url https://target.ctf --wordlist examples/wordlist.txt
syctf web-helper param-fuzzer --url 'https://target.ctf/item?id=1'
```

### 5) Generate exploit skeleton with AI

```bash
syctf ai exploit ./binary/chall --remote challenge.ctf.net:31337
```

### 6) Generate writeup from session state

```bash
syctf ai writeup
```

## Real CTF Workflow Examples

### Workflow A: Web challenge first-pass triage

```bash
syctf workspace init web_ssti
syctf web-helper quick-recon 'https://web-challenge.ctf'
syctf web-helper quick-fuzz 'https://web-challenge.ctf/search?q=test'
syctf web-helper param-fuzzer --url 'https://web-challenge.ctf/item?id=1' --payload '{{7*7}}'
```

What to look for:
- reflected payloads
- SQL/error signatures
- suspicious status codes and hidden paths

### Workflow B: Pwn ELF triage to exploit draft

```bash
syctf workspace init babybof
syctf workspace set-target ./binary/babybof
syctf pwn-helper elf-analyze ./binary/babybof
syctf pwn-helper cyclic generate --length 300
syctf ai exploit ./binary/babybof --remote host.ctf.net:9001
```

### Workflow C: Encoded flag recovery chain

```bash
syctf misc smart-decode 'Vm0weE5GUXhTbGhoV0doVFYwZG9XRmx0ZEdGV2JYaHJXa2R3VjFKcmNIbFdSVVpYVWpGS1NWWXhjRmRXTVhCS1VteHdVbFJ0VGs5WFJsWnhWakZhYzFwV1NrZFRiRkpIV2tWYWQySkVSbFZXTTFKR1lYcGFWbGRyV2xkbFJtUnZZbFZhV0ZkR1ZuUmFWR2hYVm1wS1MyVkdXbkpoTTJoVVZqQmFNMVJ0Y0U5a1ZscHpXa1JTVjFaV1pEQldWbHBQ'
syctf crypto-helper caesar-brute --text 'Gur synt vf abg urer'
```

## Plugin System

SYCTF supports external module packs loaded at runtime.

### Install/list/info/remove plugins

```bash
syctf plugin install owner/repo
syctf plugin list
syctf plugin info owner_repo
syctf plugin remove owner_repo
```

How it works:
- downloads plugin zip from GitHub main branch
- validates plugin manifest
- installs plugin dependencies if requirements.txt exists
- loads modules from plugin modules/ tree

Expected plugin package basics:
- plugin.json with name/version/author/modules
- modules/ containing plugin module files

## AI Mode

AI mode is local-first and integrated into shell workflows.

### Enter AI mode in shell

```text
SYCTF > ai
```

AI shell commands:
- ai: start chat mode
- ai exploit <binary_path> [--remote host:port]
- ai writeup [--model model_name]
- ai decode
- ai recon-plan

### AI setup and model health

```bash
syctf ai-setup
```

This checks:
- system resources
- Ollama server reachability
- recommended model availability

## Demo

Quick local demo run:

```bash
# shell workflow
syctf shell

# in shell
list
use misc/smart-decode
run SGVsbG8gQ1RGIQ==
back
ai
```

Visual demo:

![SYCTF Demo](docs/demo.gif)

## Performance Tips

- Use workspace mode early to keep outputs organized.
- Keep AI models local and warm (avoid repeated cold starts).
- Tune request timeouts only when target is slow/noisy.
- Prefer quick-recon before heavier fuzzing.
- Use smaller models (phi) on low-RAM systems.
- In VM workflows, keep host/guest network latency low.

## Troubleshooting

### syctf command not found

Use module form first:

```bash
python -m syctf --help
```

If that works, your venv PATH is not active. Re-activate venv and retry.

### Ollama model missing

Symptoms:
- Model missing: deepseek-coder:6.7b
- Available models: [...]

Fix:

```bash
ollama pull deepseek-coder:6.7b
syctf ai-setup
```

### AI engine offline / host connection failed

Check Ollama:

```bash
ollama serve
```

Hybrid mode (Kali -> host) check:

```bash
export OLLAMA_HOST=http://<host-ip>:11434
curl http://<host-ip>:11434/api/tags
```

### AI memory/runtime pressure

Symptoms:
- model load failures
- slow generation
- OOM or timeout behavior

Fix strategy:
- switch to smaller model (phi)
- close memory-heavy apps
- increase VM RAM allocation
- keep one active model during CTF sessions

### pwntools errors on Windows

Pwntools is optional and Windows pwn support can be limited.

Recommended:
- run pwn workflows in Kali/Linux
- install extras there with pip install 'syctf[pwn]'

### Plugin install issues

Checklist:
- plugin repo exists and is reachable
- plugin.json is valid
- modules/ exists in plugin package
- requirements install successfully

## Disclaimer

Use SYCTF only in legal environments (CTFs, labs, authorized assessments).
You are responsible for complying with applicable laws and competition rules.


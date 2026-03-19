# SYCTF | AI-Native CTF Automation Framework

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-2ea44f)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-0b7285)](https://github.com/SYCO7/SYCTF)

SYCTF is a terminal-first CTF framework built for players who want speed, structure, and local AI power without losing manual control.

It combines:
- deterministic modules for recon, web, pwn, crypto, rev, and misc workflows
- reproducible challenge workspaces with session context
- local or hybrid Ollama-backed AI for exploit and writeup acceleration
- plugin-based extensibility for team-specific playbooks

Fast enough for live CTF pressure, structured enough for long-running team operations.

## Table of Contents

- [Why SYCTF](#why-syctf)
- [Feature Highlights](#feature-highlights)
- [Hybrid AI Architecture](#hybrid-ai-architecture)
- [Architecture Diagram (ASCII)](#architecture-diagram-ascii)
- [Recommended Setup](#recommended-setup)
- [Installation](#installation)
  - [Windows PowerShell](#windows-powershell)
  - [Kali Linux](#kali-linux)
  - [Optional pwn extras](#optional-pwn-extras)
- [Quick Start](#quick-start)
- [Step-by-Step Usage](#step-by-step-usage)
- [Real CTF Workflow Playbooks](#real-ctf-workflow-playbooks)
- [Plugin System](#plugin-system)
- [AI Mode](#ai-mode)
- [Demo: 5-Minute Run](#demo-5-minute-run)
- [Performance Tips](#performance-tips)
- [Troubleshooting](#troubleshooting)
- [Security and Legal Use](#security-and-legal-use)

## Why SYCTF

Most CTF time is lost in repetitive glue work:
- rebuilding the same workspace layout
- re-running low-signal recon steps
- jumping between tools and notes
- rewriting exploit/writeup skeletons from scratch

SYCTF keeps everything in one operator-focused CLI surface so you spend time exploiting, not wiring.

## Feature Highlights

- ⚡ Terminal-native command flow with optional interactive shell
- 🧠 Recursive smart decoding and crypto helper utilities
- 🌐 Practical web recon and fuzz helpers for first-pass triage
- 🧩 ELF analysis + cyclic/offset helpers for pwn workflows
- 🤖 AI-assisted exploit skeleton generation
- 📝 AI-assisted writeup generation from workspace/session context
- 🗂 Workspace scaffolding with persistent state
- 🔌 Plugin marketplace support for external module packs

## Hybrid AI Architecture

SYCTF supports a battle-tested hybrid model used by many players:

- Ollama runs on the host machine (Windows or Linux desktop)
- SYCTF runs inside a Kali VM
- Kali points to host Ollama via OLLAMA_HOST

This gives you:
- stronger model performance on host hardware
- clean offensive tooling inside Kali
- local/private inference path without cloud dependency

### Hybrid Mode: Host Ollama + Kali SYCTF

1. Start Ollama on the host machine.
2. Find host IP reachable from Kali VM.
3. Export OLLAMA_HOST inside Kali.
4. Verify model API reachability.
5. Run SYCTF AI commands from Kali.

Host example (PowerShell):

```powershell
ollama serve
ollama pull deepseek-coder:6.7b
```

Kali example (bash):

```bash
export OLLAMA_HOST=http://192.168.56.1:11434
curl http://192.168.56.1:11434/api/tags
syctf ai-setup
```

## Architecture Diagram (ASCII)

```text
                            +----------------------------------+
                            | Host Machine (Windows/Linux)     |
                            |----------------------------------|
                            | Ollama Server                    |
                            | Models: phi / deepseek / llama   |
                            | Port: 11434                      |
                            +----------------+-----------------+
                                             |
                          HTTP via OLLAMA_HOST
                                             |
                                             v
+-----------------------------------------------------------------------+
| Kali VM (CTF Operator Environment)                                     |
|------------------------------------------------------------------------|
|  SYCTF CLI / Shell                                                     |
|      |                                                                  |
|      +--> Module Loader --> recon / web / pwn / crypto / rev / misc   |
|      |                                                                  |
|      +--> AI Layer --> exploit generation / writeup generation / chat  |
|      |                                                                  |
|      +--> Workspace System --> binary/ exploit/ decoded/ notes/ scripts|
+-----------------------------------------------------------------------+
```

## Recommended Setup

Use this baseline for stable performance:

- Python: 3.10 or 3.11 preferred (3.9+ supported)
- RAM: 16 GB+ recommended for deepseek-coder:6.7b
- Disk: SSD strongly recommended
- VM networking: bridged or host-only with stable IP routing
- Core tools on Kali for pwn: gdb, build-essential, python3-dev
- Models:
  - low RAM: phi
  - balanced: deepseek-coder:6.7b
  - high-end: codellama:13b

## Installation

### Windows PowerShell

```powershell
git clone https://github.com/SYCO7/SYCTF.git
cd SYCTF

py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -e .

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

sudo apt update
sudo apt install -y python3-venv python3-pip build-essential gdb

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
pip install -e .

# verify
syctf --help
```

### Optional pwn extras

Pwntools is optional and not included in the base install.

Install pwn extras:

```bash
pip install "syctf[pwn]"
```

Windows note:
- SYCTF runs on Windows, but advanced pwn flows may be limited.
- Auto-corefile workflows are Linux-oriented.
- For reliable pwn pipelines, run pwn modules in Kali/Linux.

## Quick Start

Linux/macOS:

```bash
syctf ai-setup
syctf shell
```

Windows PowerShell:

```powershell
syctf ai-setup
syctf shell
```

No PATH yet?

```bash
python -m syctf --help
python -m syctf shell
```

## Step-by-Step Usage

### 1) Initialize challenge workspace

```bash
syctf workspace init babyrop
```

Creates:
- binary/
- exploit/
- decoded/
- notes/
- scripts/

Workspace root location:
- Linux/Kali: ~/.syctf/workspaces/babyrop
- Windows: C:\Users\<you>\.syctf\workspaces\babyrop

### 2) Set target binary

```bash
syctf workspace set-target ./binary/chall
```

The relative target path is resolved inside the active workspace root.

### 3) Triage + helper modules

```bash
syctf pwn-helper elf-analyze ./binary/chall
syctf pwn-helper cyclic generate --length 300
syctf misc smart-decode "U0dWc2JHOD0="
syctf crypto-helper hash-ident --hash 5d41402abc4b2a76b9719d911017c592
```

### 4) Web-first recon chain

```bash
syctf web-helper quick-recon https://target.ctf
syctf web-helper quick-fuzz "https://target.ctf/search?q=test"
syctf web-helper param-fuzzer --url "https://target.ctf/item?id=1"
```

### 5) AI exploit skeleton

```bash
syctf ai exploit ./binary/chall --remote challenge.ctf.net:31337
```

### 6) AI writeup from workspace context

```bash
syctf ai writeup --model deepseek-coder:6.7b
```

## Real CTF Workflow Playbooks

### Workflow A: Web challenge first pass

```bash
syctf workspace init web_ssti
syctf web-helper quick-recon "https://web-challenge.ctf"
syctf web-helper quick-fuzz "https://web-challenge.ctf/search?q=test"
syctf web-helper param-fuzzer --url "https://web-challenge.ctf/item?id=1" --payload "{{7*7}}"
```

Signals to hunt:
- reflected payload behavior
- backend error leakage
- hidden endpoints and weak params

### Workflow B: Pwn ELF to exploit draft

```bash
syctf workspace init babybof
syctf workspace set-target ./binary/babybof
syctf pwn-helper elf-analyze ./binary/babybof
syctf pwn-helper cyclic generate --length 500
syctf ai exploit ./binary/babybof --remote host.ctf.net:9001
```

### Workflow C: Encoding and crypto chain

```bash
syctf misc smart-decode "Vm0weE5GUXhTbGhoV0doVFYwZG9XRmx0ZEdGV2JYaHJXa2R3VjFKcmNIbFdSVVpYVWpGS1NWWXhjRmRXTVhCS1VteHdVbFJ0VGs5WFJsWnhWakZhYzFwV1NrZFRiRkpIV2tWYWQySkVSbFZXTTFKR1lYcGFWbGRyV2xkbFJtUnZZbFZhV0ZkR1ZuUmFWR2hYVm1wS1MyVkdXbkpoTTJoVVZqQmFNMVJ0Y0U5a1ZscHpXa1JTVjFaV1pEQldWbHBQ"
syctf crypto-helper caesar-brute --text "Gur synt vf abg urer"
```

## Plugin System

SYCTF can load external module packs from GitHub.

### Operator commands

```bash
syctf plugin install owner/repo
syctf plugin list
syctf plugin info owner_repo
syctf plugin remove owner_repo
```

How install works:
- downloads repository main branch zip archive
- validates plugin.json schema
- checks module package layout
- installs plugin requirements if requirements.txt exists
- registers modules dynamically at runtime

### Plugin package requirements

- plugin.json with at least: name, version, author, modules
- modules/ directory containing plugin module files

Minimal plugin.json example:

```json
{
  "name": "web-ssti-pack",
  "version": "0.1.0",
  "author": "team-red",
  "modules": ["web/ssti-scanner"],
  "requires_syctf_version": "0.1.0"
}
```

## AI Mode

SYCTF AI is local-first and designed for CTF operator workflows.

### CLI AI commands

```bash
syctf ai-setup
syctf ai exploit ./binary/chall --remote host:port
syctf ai writeup --model deepseek-coder:6.7b
```

### In-shell AI commands

```text
SYCTF > ai
SYCTF > ai decode
SYCTF > ai recon-plan
SYCTF > ai exploit ./binary/chall --remote host:port
SYCTF > ai writeup --model deepseek-coder:6.7b
```

### What AI mode is best at

- category detection and attack path suggestions
- exploit skeleton drafts using ELF metadata
- quick writeup generation from recorded session context

### What AI mode is not

- not a flag oracle
- not a substitute for manual verification
- not a replacement for challenge-specific reasoning

## Demo: 5-Minute Run

### 1) Start shell and inspect modules

```bash
syctf shell
```

Inside shell:

```text
list
use misc/smart-decode
run SGVsbG8gQ1RGIQ==
back
ai
```

### 2) Run a real challenge scaffold flow

Linux/Kali:

```bash
syctf workspace init demo_challenge
cp ./path/to/chall ~/.syctf/workspaces/demo_challenge/binary/chall
syctf workspace set-target ./binary/chall
syctf pwn-helper elf-analyze ./binary/chall
syctf ai writeup
```

Windows PowerShell:

```powershell
syctf workspace init demo_challenge
Copy-Item .\path\to\chall $HOME\.syctf\workspaces\demo_challenge\binary\chall
syctf workspace set-target .\binary\chall
syctf pwn-helper elf-analyze .\binary\chall
syctf ai writeup
```

Visual preview:

![SYCTF Demo](docs/demo.gif)

## Performance Tips

- Initialize workspace early so artifacts are automatically organized.
- Keep Ollama running during CTF sessions to avoid cold start latency.
- Use quick-recon before heavier fuzz routines.
- Select model size based on available RAM to avoid swapping.
- In hybrid mode, keep host and Kali VM on low-latency network path.
- For pwn heavy tasks, use Kali/Linux with optional pwn extras installed.

## Troubleshooting

### syctf command not found

```bash
python -m syctf --help
```

If this works, your environment PATH is not active. Re-activate your virtual environment.

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Linux:

```bash
source .venv/bin/activate
```

### AI engine offline or host unreachable

Check Ollama process:

```bash
ollama serve
```

Hybrid check from Kali:

```bash
export OLLAMA_HOST=http://<host-ip>:11434
curl http://<host-ip>:11434/api/tags
```

### Model missing error

Symptom examples:
- Model missing: deepseek-coder:6.7b
- Available models: [...]

Fix:

```bash
ollama pull deepseek-coder:6.7b
syctf ai-setup
```

### AI memory/runtime pressure (OOM, stalled generation)

Fix sequence:
- switch to smaller model (for example phi)
- close memory-heavy applications
- allocate more RAM to Kali VM
- reduce parallel tooling load

### pwntools issues on Windows

- pwntools support on Windows can be partial depending on workflow
- auto corefile offset paths are Linux-first
- best practice is Kali/Linux for advanced pwn operations

Install optional pwn extras in Linux:

```bash
pip install "syctf[pwn]"
```

### Plugin installation failures

Checklist:
- repository exists and is reachable
- plugin.json is valid and complete
- modules/ directory exists in plugin package
- plugin dependencies install successfully

## Security and Legal Use

Use SYCTF only in legal, authorized environments:
- CTF platforms
- local labs
- explicitly authorized assessments

You are responsible for compliance with laws and competition rules.
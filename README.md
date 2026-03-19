# SYCTF

AI-powered terminal CTF automation framework.

SYCTF helps beginners and experienced players move faster during CTFs by automating repetitive tasks while keeping everything in a clear command-line workflow.

## 1. 🚀 What Is SYCTF

SYCTF is built for practical, real CTF work.

- Recursive decoding: Quickly peel layered encodings (base64, hex, URL, XOR, and more) to recover useful plaintext.
- Pwn triage: Inspect binaries fast (protections, symbols, strings, exploit hints) before writing payloads.
- Exploit skeleton generation: Generate a starter pwntools template with context-aware guidance.
- Workspace organization: Keep artifacts cleanly separated in per-challenge folders.

## 2. ✨ Features

- Interactive shell mode: Work from one command interface instead of many ad-hoc scripts.
- AI-assisted workflows: Use a local model for practical hints and writeup support.
- Modular architecture: Recon, web, pwn, reverse, crypto, misc, and plugin packs.
- Safe-by-default behavior: Input validation, request timeouts, bounded operations, and guarded execution paths.
- Persistent workspace and cache support: Save outputs, notes, and expensive analysis results for reuse.
- Plugin pack support: Install, list, inspect, and remove external module packs.

## 📦 Installation

Follow these steps from top to bottom if you are setting up SYCTF for the first time.

### 1. Clone Repository

```bash
git clone https://github.com/SYCO7/SYCTF.git
cd SYCTF
```

### 2. Create Virtual Environment

```bash
python -m venv .venv
```

### 3. Activate Virtual Environment

```bash
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# Linux / macOS
source .venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Verify Installation

```bash
python syctf.py --help
```

### 6. Start SYCTF Shell

```bash
python syctf.py shell
```

## 4. 🤖 Setup AI (Offline)

SYCTF supports local AI workflows using Ollama (no cloud key required).

1. Install Ollama from the official Ollama website.
2. Pull a local coding model:

```bash
ollama pull deepseek-coder
```

3. Run SYCTF AI setup:

```bash
python syctf.py ai-setup
```

If you use the shell command alias instead of `python syctf.py`, you can run:

```bash
syctf ai-setup
```

## 5. 🧠 Basic Usage

Start shell mode (works on every platform without PATH setup):

```bash
python syctf.py shell
```

You can also use the shorter command after installing an entrypoint:

```bash
syctf shell
```

Decode a value quickly:

```bash
syctf misc smart-decode SGVsbG8=
```

Generate exploit starter:

```bash
syctf ai exploit ./chall
```

If `syctf` is not on PATH yet, use:

```bash
python syctf.py shell
python syctf.py misc smart-decode SGVsbG8=
python syctf.py ai exploit ./chall
```

## 6. 🗂 Workspace

Initialize a dedicated challenge workspace:

```bash
syctf workspace init babyrop
```

This creates structured directories for binaries, exploits, decoded outputs, notes, and scripts.

## 7. 🔌 Plugins

Install a plugin pack:

```bash
syctf plugin install pack
```

Helpful plugin commands:

```bash
syctf plugin list
syctf plugin info pack
syctf plugin remove pack
```

## 8. 🎥 Demo Section

Demo GIF placeholder:

```text
docs/demo.gif
```

![SYCTF Demo](docs/demo.gif)

When ready, add your demo here:

```markdown
![SYCTF Demo](docs/demo.gif)
```

## 9. 🛡 Disclaimer

SYCTF is for educational use, legal CTF competitions, and authorized security testing only.

Do not use this tool against systems you do not own or have explicit permission to assess.


# 🚀 SYCTF — AI Powered CTF Automation Framework

An AI-powered terminal framework that helps CTF players automate repetitive tasks and solve challenges faster.

## ✨ Features

- Recursive smart decoding engine
- Binary exploitation triage analyzer
- AI exploit skeleton generator
- Workspace based challenge organization
- Offline local AI assistant (Ollama)
- Plugin marketplace support
- Web recon helpers
- Reverse engineering triage

## 📦 Installation

### Clone

```bash
git clone https://github.com/SYCO7/SYCTF.git
cd SYCTF
```

### Create virtual environment

```bash
python -m venv .venv
```

### Activate

Linux / macOS:

```bash
source .venv/bin/activate
```

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

### Install

```bash
pip install .
```

If the `syctf` command is not available in your terminal yet, use:

```bash
python -m syctf shell
```

## 🤖 Setup Offline AI

Install Ollama from https://ollama.com

Then:

```bash
ollama pull deepseek-coder:6.7b
syctf ai-setup
```

## 🧠 Basic Usage

Start shell:

```bash
syctf shell
```

Decode example:

```bash
misc smart-decode SGVsbG8=
```

Generate exploit template:

```bash
ai exploit ./chall
```

Create workspace:

```bash
workspace init babyrop
```

## 🎥 Demo

![SYCTF Demo](docs/demo.gif)

## 🛡 Disclaimer

Educational and legal CTF usage only.


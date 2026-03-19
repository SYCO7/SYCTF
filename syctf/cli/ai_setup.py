import shutil
import subprocess
import psutil
from rich import print
from rich.panel import Panel

from syctf.ai.client import get_ollama_client, get_ollama_host


def detect_resources():
    ram = round(psutil.virtual_memory().total / (1024**3))
    cpu = psutil.cpu_count()

    gpu = False
    try:
        subprocess.run(
            ["nvidia-smi"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        gpu = True
    except Exception:
        gpu = False

    return ram, cpu, gpu


def recommend_model(ram):
    if ram < 8:
        return "phi"
    elif ram <= 16:
        return "deepseek-coder:6.7b"
    else:
        return "codellama:13b"


def check_ollama_installed():
    return shutil.which("ollama") is not None


def check_ollama_server():
    host = get_ollama_host()
    client = get_ollama_client(timeout=2.0)
    try:
        client.list()
        return True
    except Exception as exc:  # noqa: BLE001
        print("AI engine offline.")
        print(f"Configured host: {host}")
        print(f"Error: {type(exc).__name__}: {exc}")
        return False


def model_installed(model):
    host = get_ollama_host()
    client = get_ollama_client(timeout=3.0)
    try:
        payload = client.list() or {}
        names = {
            entry.get("name", "")
            for entry in payload.get("models", [])
            if isinstance(entry, dict)
        }
        return model in names
    except Exception as exc:  # noqa: BLE001
        print("AI engine offline.")
        print(f"Configured host: {host}")
        print(f"Error: {type(exc).__name__}: {exc}")
        return False


def pull_model(model):
    print(f"[cyan]Pulling model {model}...[/cyan]")
    subprocess.run(["ollama", "pull", model])


def run_ai_setup():
    print(Panel("SYCTF AI Setup", style="bold green"))

    ram, cpu, gpu = detect_resources()

    print(f"RAM: {ram} GB")
    print(f"CPU cores: {cpu}")
    print(f"GPU detected: {gpu}")

    model = recommend_model(ram)

    print(f"\nRecommended model: [yellow]{model}[/yellow]\n")

    if not check_ollama_installed():
        print("[red]Ollama not installed.[/red]")
        print("Install from: https://ollama.com")
        return

    if not check_ollama_server():
        print("[red]Ollama server not running.[/red]")
        print("Run: ollama serve")
        return

    if not model_installed(model):
        choice = input(f"Install model {model}? (y/n): ")
        if choice.lower() == "y":
            pull_model(model)
        else:
            print("Skipping model install.")
            return

    print("\n[green]AI setup complete.[/green]")
    print("Run: python -m syctf shell -> ai")
import shutil
import subprocess
import psutil
from rich import print
from rich.panel import Panel

from syctf.ai.client import get_ai_connection_diagnostics


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
    """Pick the best-balance model for the box's RAM.

    Qwen2.5-Instruct: strong instruction-following + tool use, well-calibrated
    (low hallucination), reliable ollama tags, fast on CPU. The sweet spot for
    SYCTF's agent in a Kali VM — see docs/ai/models.md.
    """

    if ram < 6:
        return "qwen2.5:3b-instruct-q4_K_M"      # ~2.2 GB, very smooth on CPU
    elif ram <= 12:
        return "qwen2.5:7b-instruct-q4_K_M"      # ~4.7 GB, best balance for 8-12 GB
    else:
        return "qwen2.5:14b-instruct-q4_K_M"     # ~9 GB, more headroom


def check_ollama_installed():
    return shutil.which("ollama") is not None


def check_ollama_server():
    diagnostics = get_ai_connection_diagnostics(model="")
    return diagnostics.connected_host is not None


def model_installed(model):
    diagnostics = get_ai_connection_diagnostics(model=model)
    return diagnostics.model_available


def show_diagnostics(model: str) -> None:
    """Render resolver diagnostics panel for connection and model readiness."""

    diagnostics = get_ai_connection_diagnostics(model=model)
    connected = diagnostics.connected_host or "unavailable"
    latency = (
        f"{diagnostics.latency_ms:.1f} ms"
        if diagnostics.latency_ms is not None
        else "unavailable"
    )
    model_state = "available" if diagnostics.model_available else "missing"

    print(
        Panel(
            f"[green]✔ Connected host:[/green] {connected}\n"
            f"[green]✔ Latency:[/green] {latency}\n"
            f"[green]✔ Model availability:[/green] {model_state}",
            title="AI Diagnostics",
            border_style="cyan",
        )
    )

    if diagnostics.available_models:
        print(f"Available models: {diagnostics.available_models}")


def pull_model(model):
    print(f"[cyan]Pulling model {model}...[/cyan]")
    subprocess.run(["ollama", "pull", model])


def run_ai_setup():
    print(Panel("SYCTF AI Setup", style="bold green"))

    from syctf.core.hardware import detect_hardware, recommend_hosted
    from syctf.core.hardware import recommend_model as hw_recommend_model

    hw = detect_hardware()
    gpu_line = (
        f"{hw.gpus[0].name} ({hw.vram_gb:.0f} GB VRAM)" if hw.has_gpu else "none (CPU-only)"
    )
    print(f"OS: {hw.os_name}{'  [VM]' if hw.is_vm else ''}")
    print(f"RAM: {hw.ram_gb} GB   CPU cores: {hw.cpu_cores}")
    print(f"GPU: {gpu_line}")

    model, why = hw_recommend_model(hw)
    print(f"\nRecommended model: [yellow]{model}[/yellow]  [dim]({why})[/dim]")
    print(f"[cyan]{recommend_hosted(hw)}[/cyan]\n")
    show_diagnostics(model)

    if not check_ollama_installed():
        print("[red]Ollama not installed.[/red]")
        print("Install from: https://ollama.com")
        return

    if not check_ollama_server():
        print("[yellow]AI engine offline — continuing without AI.[/yellow]")
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
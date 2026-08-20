"""Cross-platform hardware detection + hardware-aware model recommendation.

Works on Linux, Windows, and macOS. Detects RAM, CPU, NVIDIA GPU/VRAM, and
whether we're inside a VM, then recommends the best local Ollama model for the
box — a bigger/stronger model when a real GPU is present, a lean one on a small
CPU-only VM — and when to reach for a hosted key instead.
"""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass, field


@dataclass(slots=True)
class GPUInfo:
    name: str
    vram_mb: int


@dataclass(slots=True)
class HardwareInfo:
    os_name: str
    is_windows: bool
    is_vm: bool
    ram_gb: float
    cpu_cores: int
    gpus: list[GPUInfo] = field(default_factory=list)

    @property
    def has_gpu(self) -> bool:
        return bool(self.gpus)

    @property
    def vram_gb(self) -> float:
        return max((g.vram_mb for g in self.gpus), default=0) / 1024.0


def _total_ram_gb() -> float:
    try:
        import psutil

        return round(psutil.virtual_memory().total / (1024**3), 1)
    except Exception:  # noqa: BLE001
        return 0.0


def _cpu_cores() -> int:
    try:
        import psutil

        return int(psutil.cpu_count(logical=True) or 0)
    except Exception:  # noqa: BLE001
        import os

        return os.cpu_count() or 0


def detect_nvidia_gpus() -> list[GPUInfo]:
    """Query NVIDIA GPUs via nvidia-smi (present on Windows + Linux with driver)."""

    try:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=4,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return []
    if out.returncode != 0:
        return []
    gpus: list[GPUInfo] = []
    for line in out.stdout.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 2:
            try:
                gpus.append(GPUInfo(name=parts[0], vram_mb=int(float(parts[1]))))
            except ValueError:
                continue
    return gpus


def _detect_vm() -> bool:
    system = platform.system()
    try:
        if system == "Linux":
            r = subprocess.run(["systemd-detect-virt"], capture_output=True, text=True, timeout=3)
            if r.returncode == 0 and r.stdout.strip() and r.stdout.strip() != "none":
                return True
            for path in ("/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"):
                try:
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        blob = fh.read().lower()
                    if any(v in blob for v in ("vmware", "virtualbox", "kvm", "qemu", "xen", "hyper-v", "innotek")):
                        return True
                except OSError:
                    continue
        elif system == "Windows":
            r = subprocess.run(["wmic", "computersystem", "get", "model"], capture_output=True, text=True, timeout=4)
            blob = r.stdout.lower()
            if any(v in blob for v in ("virtual", "vmware", "kvm", "qemu", "hyper-v")):
                return True
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return False
    return False


def detect_hardware() -> HardwareInfo:
    system = platform.system()
    return HardwareInfo(
        os_name=f"{system} {platform.release()}",
        is_windows=(system == "Windows"),
        is_vm=_detect_vm(),
        ram_gb=_total_ram_gb(),
        cpu_cores=_cpu_cores(),
        gpus=detect_nvidia_gpus(),
    )


def recommend_model(hw: HardwareInfo) -> tuple[str, str]:
    """Return (ollama model tag, one-line rationale) best matched to the box."""

    if hw.has_gpu:
        vram = hw.vram_gb
        if vram >= 22:
            return "qwen2.5:32b-instruct-q4_K_M", f"{vram:.0f} GB VRAM — run a 32B locally (or deepseek-r1:32b)"
        if vram >= 14:
            return "qwen2.5:14b-instruct-q4_K_M", f"{vram:.0f} GB VRAM — a 14B fits comfortably"
        if vram >= 8:
            return "qwen2.5:7b-instruct-q4_K_M", f"{vram:.0f} GB VRAM — fast 7B on GPU"
        return "qwen2.5:3b-instruct-q4_K_M", f"{vram:.0f} GB VRAM — 3B on GPU"

    # CPU-only: bounded by system RAM (VM-friendly)
    ram = hw.ram_gb
    if ram < 6:
        return "qwen2.5:3b-instruct-q4_K_M", f"{ram:.0f} GB RAM, CPU-only — 3B stays smooth"
    if ram <= 12:
        return "qwen2.5:7b-instruct-q4_K_M", f"{ram:.0f} GB RAM, CPU-only — 7B is the sweet spot"
    return "qwen2.5:14b-instruct-q4_K_M", f"{ram:.0f} GB RAM, CPU-only — room for a 14B"


def recommend_hosted(hw: HardwareInfo) -> str:
    """Suggest when/what hosted key to use alongside the local pick."""

    if hw.has_gpu and hw.vram_gb >= 14:
        return "Strong GPU — you can also run reasoning models locally (deepseek-r1:14b/32b)."
    if not hw.has_gpu and hw.ram_gb < 8:
        return "Low RAM, no GPU — for hard challenges use a free hosted key (Groq deepseek-r1-distill, very fast)."
    return "Hardest challenges → a hosted reasoning key: DeepSeek-R1 or NVIDIA Nemotron Ultra."

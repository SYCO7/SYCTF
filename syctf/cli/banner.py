"""Legend-grade startup renderer for SYCTF CLI."""

from __future__ import annotations

import platform
import time
from dataclasses import dataclass
from pathlib import Path

from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from syctf.ai.client import get_ollama_client, get_ollama_host
from syctf.core.plugin_marketplace import PluginManager
from syctf import modules

OWNER = "Tanmoy Mondal"
GITHUB_URL = "https://github.com/SYCO7"
LINKEDIN_URL = "https://www.linkedin.com/in/tanmoy-mondal-11070334b/"
PORTFOLIO_URL = "https://cybersyco.vercel.app/"

VERSION_LABEL = "SYCTF v0.1-alpha"
AI_MODE_LABEL = "AI Mode Enabled"
DEFAULT_MODEL = "deepseek-coder:6.7b"

# Cinematic, sharp-edged logo with embedded [AI] tag and underline/shadow accent.
ASCII_LOGO = [
    "  ███████╗██╗   ██╗ ██████╗████████╗███████╗   [AI]",
    "  ██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝",
    "  ███████╗ ╚████╔╝ ██║        ██║   █████╗  ",
    "  ╚════██║  ╚██╔╝  ██║        ██║   ██╔══╝  ",
    "  ███████║   ██║   ╚██████╗   ██║   ██║     ",
    "  ╚══════╝   ╚═╝    ╚═════╝   ╚═╝   ╚═╝     ",
    "  ─────────────────────────────────────────────────────",
    "  ░▒▓ offensive automation / exploit acceleration / capture workflow ▓▒░",
]


@dataclass(slots=True)
class StartupDiagnostics:
    """Runtime diagnostics displayed during startup."""

    python_version: str
    ai_engine_online: bool
    model_loaded: bool
    plugins_loaded: int
    modules_available: int


def _build_logo(lines: list[str] | None = None) -> Text:
    """Build gradient-styled logo text block."""

    source = lines if lines is not None else ASCII_LOGO
    styles = [
        "bold bright_green",
        "bold spring_green3",
        "bold green",
        "bold cyan",
        "bold bright_cyan",
        "bold cyan",
        "dim bright_cyan",
        "dim green",
    ]

    text = Text()
    for idx, line in enumerate(source):
        text.append(line, style=styles[idx % len(styles)])
        if idx < len(source) - 1:
            text.append("\n")
    return text


def _collect_diagnostics() -> StartupDiagnostics:
    """Collect startup diagnostics with short network timeout for fast render."""

    pyver = f"{platform.python_version()} ({platform.python_implementation()})"
    ai_online = False
    model_loaded = False

    def _available_models(payload: object) -> list[str]:
        models_any = getattr(payload, "models", None)
        if models_any is None and isinstance(payload, dict):
            models_any = payload.get("models", [])
        if models_any is None:
            models_any = []

        out: list[str] = []
        for item in models_any:
            name = ""
            if isinstance(item, str):
                name = item
            elif isinstance(item, dict):
                name = str(item.get("model") or item.get("name") or "")
            else:
                name = str(getattr(item, "model", "") or getattr(item, "name", ""))
            name = name.strip()
            if name and name not in out:
                out.append(name)
        return out

    try:
        client = get_ollama_client(timeout=0.25)
        payload = client.list()
        ai_online = True
        model_loaded = DEFAULT_MODEL in _available_models(payload)
    except Exception as exc:  # noqa: BLE001
        ai_online = False
        model_loaded = False
        print(
            f"[SYCTF AI] Ollama diagnostics unavailable for {get_ollama_host()}: "
            f"{type(exc).__name__}: {exc}"
        )

    manager = PluginManager()
    plugins_loaded = len(manager.list_plugins())
    modules_available = _count_available_modules(manager)

    return StartupDiagnostics(
        python_version=pyver,
        ai_engine_online=ai_online,
        model_loaded=model_loaded,
        plugins_loaded=plugins_loaded,
        modules_available=modules_available,
    )


def _count_available_modules(manager: PluginManager) -> int:
    """Count available module files from core modules and installed plugins."""

    roots: list[Path] = [Path(modules.__file__).resolve().parent]
    roots.extend(manager.discover_module_roots())

    count = 0
    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        for py_file in root.rglob("*.py"):
            if py_file.name.startswith("__"):
                continue
            count += 1
    return count


def _status_line(ok: bool, label: str, value: str, warn: bool = False) -> Text:
    """Return color-semantic status line text with symbolic marker."""

    marker = "✔" if ok else "⚠"
    marker_style = "bold green" if ok else "bold yellow" if warn else "bold red"
    value_style = "green" if ok else "yellow" if warn else "red"

    text = Text()
    text.append(f"[{marker}] ", style=marker_style)
    text.append(label, style="bold white")
    text.append(": ", style="white")
    text.append(value, style=value_style)
    return text


def _diagnostics_panel(diag: StartupDiagnostics) -> Panel:
    """Build system diagnostics panel."""

    ai_text = "ONLINE" if diag.ai_engine_online else "OFFLINE"
    model_text = "LOADED" if diag.model_loaded else "NOT LOADED"

    lines = [
        _status_line(True, "Python", diag.python_version),
        _status_line(diag.ai_engine_online, "AI Engine", ai_text),
        _status_line(diag.model_loaded, "Ollama Model", model_text, warn=True),
        _status_line(diag.plugins_loaded > 0, "Plugins", str(diag.plugins_loaded), warn=True),
        _status_line(diag.modules_available > 0, "Modules", str(diag.modules_available), warn=True),
        Text(),
        Text(f"{VERSION_LABEL}  |  {AI_MODE_LABEL}", style="bold bright_cyan"),
    ]

    body = Group(*lines)
    return Panel(
        body,
        title="[bold bright_cyan]System Diagnostics[/bold bright_cyan]",
        border_style="bright_cyan",
        padding=(1, 1),
    )


def _branding_panel() -> Panel:
    """Build owner and branding information panel with hyperlinks."""

    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold green", justify="right", no_wrap=True)
    grid.add_column(style="white", overflow="fold")

    grid.add_row("Owner:", f"[bold white]{OWNER}[/bold white]")
    grid.add_row("GitHub:", f"[link={GITHUB_URL}]{GITHUB_URL}[/link]")
    grid.add_row("LinkedIn:", f"[link={LINKEDIN_URL}]{LINKEDIN_URL}[/link]")
    grid.add_row("Portfolio:", f"[link={PORTFOLIO_URL}]{PORTFOLIO_URL}[/link]")

    return Panel(
        grid,
        title="[bold bright_cyan]Operator Identity[/bold bright_cyan]",
        border_style="bright_cyan",
        padding=(1, 1),
    )


def _logo_panel() -> Panel:
    """Build logo panel with tagline."""

    tagline = Text("Automate. Exploit. Capture.", style="italic dim green")
    body = Group(Align.center(_build_logo()), Text(""), Align.center(tagline))
    return Panel(
        body,
        title="[bold bright_cyan]SYCTF[/bold bright_cyan]",
        border_style="bright_cyan",
        padding=(1, 2),
    )


def _footer_line(width: int, shimmer: bool = False) -> Text:
    """Build cyber footer separator with optional shimmer style."""

    label = " OFFENSIVE SECURITY TERMINAL FRAMEWORK "
    fill = "═"
    usable = max(20, width - 2)
    pad = max(2, (usable - len(label)) // 2)
    line = f"{fill * pad}{label}{fill * pad}"
    if len(line) < usable:
        line = line + (fill * (usable - len(line)))
    style = "bold bright_cyan" if shimmer else "bold cyan"
    return Text(line[:usable], style=style)


def _render_cinematic(console: Console, diag: StartupDiagnostics) -> None:
    """Render startup in cinematic multi-panel layout."""

    top = Columns([_logo_panel(), _diagnostics_panel(diag)], equal=True, expand=True)
    bottom = Columns([_branding_panel()], expand=True)
    console.print(top)
    console.print(bottom)


def _render_compact(console: Console, diag: StartupDiagnostics) -> None:
    """Render startup in compact stacked layout for narrow terminals."""

    console.print(_logo_panel())
    console.print(_diagnostics_panel(diag))
    console.print(_branding_panel())


def render_startup(console: Console, *, animate: bool = True) -> None:
    """Render full startup experience with bounded sub-second animation."""

    width = int(getattr(console.size, "width", 120))

    if animate:
        # Typing effect for logo reveal.
        with Live(console=console, refresh_per_second=30, transient=True) as live:
            live.update(
                Panel(
                    Align.center(_build_logo(ASCII_LOGO[:4])),
                    title="[bold bright_cyan]SYCTF[/bold bright_cyan]",
                    border_style="bright_cyan",
                    padding=(1, 2),
                )
            )
            time.sleep(0.08)
            live.update(_logo_panel())
            time.sleep(0.08)

    with console.status("[cyan]Syncing diagnostics...[/cyan]", spinner="dots"):
        diag = _collect_diagnostics()
        if animate:
            time.sleep(0.18)

    if width < 100:
        _render_compact(console, diag)
    else:
        _render_cinematic(console, diag)

    footer = _footer_line(width, shimmer=animate)
    console.print(Align.center(footer))
    if animate:
        time.sleep(0.06)
    console.print()


def show_banner(console: Console) -> None:
    """Backward-compatible alias for existing startup call-sites."""

    render_startup(console)

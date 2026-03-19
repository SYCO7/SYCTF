"""Banner and terminal branding for SYCTF."""

from __future__ import annotations

import random
import string
import time

from pyfiglet import Figlet
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from syctf.core.types import AppConfig


def _random_stream(width: int) -> str:
    """Generate one line of matrix-like stream characters."""

    alphabet = string.hexdigits.lower() + "01"
    return "".join(random.choice(alphabet) for _ in range(width))


def show_banner(console: Console, config: AppConfig) -> None:
    """Render animated banner then print SYCTF metadata."""

    figlet = Figlet(font="slant")
    ascii_logo = figlet.renderText("SYCTF")

    with Live(console=console, refresh_per_second=18, transient=True) as live:
        for _ in range(12):
            glitch = "\n".join(_random_stream(72) for _ in range(7))
            text = Text(glitch, style="bold green")
            live.update(Panel(text, title="[blink]SYCTF BOOT[/blink]", border_style="green"))
            time.sleep(0.05)

    logo_text = Text(ascii_logo, style="bold bright_green")
    console.print(Panel(logo_text, border_style="bright_green"))
    console.print("[bold cyan]Automate. Exploit. Capture.[/bold cyan]")
    console.print(f"[green]Owner:[/green] {config.owner}")
    console.print(f"[green]GitHub:[/green] {config.github}")
    console.print(f"[green]LinkedIn:[/green] {config.linkedin}")
    console.print(f"[green]Portfolio:[/green] {config.portfolio}")
    console.print()

"""`syctf solve` -- run the autonomous engine and render the result."""

from __future__ import annotations

import os

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def run_solve(
    target: str,
    *,
    flag_format: str | None = None,
    use_ai: bool = True,
    budget: int = 12,
    ensemble: int = 1,
    provider: str | None = None,
    model: str | None = None,
    console: Console | None = None,
) -> int:
    """Solve ``target`` autonomously and print a report. Returns exit code."""

    console = console or Console()

    if provider:
        os.environ["SYCTF_AI_PROVIDER"] = provider
    if model:
        os.environ["SYCTF_AI_MODEL"] = model
    if provider or model:
        label = f"{provider or 'current'}:{model or 'default'}"
        console.print(f"[dim]AI override → {label}[/dim]")

    from syctf.engine import Engine

    console.print(Panel(f"Autonomous solve: [cyan]{target}[/cyan]", border_style="magenta"))
    engine = Engine(use_ai=use_ai)
    result = engine.solve(target, flag_format=flag_format, budget=budget, use_ai=use_ai, ensemble=ensemble)

    table = Table(show_header=False, box=None)
    table.add_row("category", result.category)
    table.add_row("steps run", str(result.steps))
    table.add_row("AI used", "yes" if result.used_ai else "no")
    if result.used_ai:
        table.add_row("confidence", f"{result.confidence:.0%}")
    console.print(table)

    if result.transcript:
        console.print(Panel("\n".join(result.transcript[-14:]), title="trace", border_style="blue"))

    if result.ai_summary:
        console.print(Panel(result.ai_summary.strip()[:2000], title="AI reasoning", border_style="cyan"))

    if result.solved:
        console.print(Panel(f"[bold green]{result.flag}[/bold green]", title="FLAG (verified)", border_style="green"))
    else:
        console.print(Panel("No verified flag yet.", title="result", border_style="yellow"))
        if result.recommended_modules:
            console.print("[bold]Recommended next modules:[/bold] " + ", ".join(result.recommended_modules))

    return 0 if result.solved else 1

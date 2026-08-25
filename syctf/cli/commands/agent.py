"""`syctf agent` -- autonomous tool-using CTF agent over real modules."""

from __future__ import annotations

import os

from rich.panel import Panel
from rich.table import Table


def run_agent(app, target: str, *, goal: str = "capture the flag", budget: int = 10, flag_format: str | None = None, provider: str | None = None, model: str | None = None) -> int:
    """Run the autonomous agent and render the outcome. Returns exit code."""

    console = app.console

    if provider:
        os.environ["SYCTF_AI_PROVIDER"] = provider
    if model:
        os.environ["SYCTF_AI_MODEL"] = model
    if provider or model:
        console.print(f"[dim]AI override → {provider or 'current'}:{model or 'default'}[/dim]")

    from syctf.ai.router import ModelRouter
    from syctf.ai.verifier import Verifier
    from syctf.engine.agent import AgentOrchestrator
    from syctf.flags.detector import FlagDetector

    flag_format = flag_format or app.context.cache.get("flag_format")
    console.print(Panel(f"SYCTF Agent — goal: [cyan]{goal}[/cyan]  target: [cyan]{target}[/cyan]", border_style="magenta"))
    router = ModelRouter()
    verifier = Verifier(detector=FlagDetector(custom_format=flag_format))
    agent = AgentOrchestrator(app.loader, app.context, router, verifier=verifier, console=console, flag_format=flag_format)
    result = agent.run(target, goal=goal, budget=budget)

    tools = Table(title="Tools invoked", show_header=True)
    tools.add_column("#", style="cyan", no_wrap=True)
    tools.add_column("Tool", style="green")
    tools.add_column("OK", style="white")
    for i, call in enumerate(result.calls, 1):
        tools.add_row(str(i), call.tool, "yes" if call.ok else "[red]no[/red]")
    if result.calls:
        console.print(tools)

    if result.solved:
        console.print(Panel(f"[bold green]{result.flag}[/bold green]", title="FLAG (verified)", border_style="green"))
        return 0

    console.print(Panel("No verified flag. See transcript below.", title="result", border_style="yellow"))
    console.print("\n".join(result.transcript[-12:]))
    console.print(
        "[dim]Agent needs a reachable AI backend (local Ollama or a hosted key). "
        "Check `syctf ai providers`; or use `syctf solve` for the deterministic pass.[/dim]"
    )
    return 1

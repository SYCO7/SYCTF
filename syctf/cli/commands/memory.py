"""`syctf memory` — show what the cross-challenge solve memory has learned."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table


def render_memory(console: Console | None = None) -> int:
    """Print solve-memory stats (categories + techniques). Returns exit code."""

    console = console or Console()
    from syctf.memory import SolveMemory

    stats = SolveMemory().stats()
    if not stats["total"]:
        console.print("[dim]No solves recorded yet — solve a few challenges and they'll show here.[/dim]")
        return 0

    console.print(f"[bold]Solves remembered:[/bold] {stats['total']}")

    cat = Table(title="By category", border_style="cyan")
    cat.add_column("Category", style="cyan")
    cat.add_column("Solved", style="green", justify="right")
    for name, count in sorted(stats["by_category"].items(), key=lambda kv: kv[1], reverse=True):
        cat.add_row(name, str(count))
    console.print(cat)

    tech = Table(title="Top techniques", border_style="cyan")
    tech.add_column("Technique", style="yellow")
    tech.add_column("Used", style="green", justify="right")
    for name, count in stats["by_technique"].items():
        tech.add_row(name, str(count))
    console.print(tech)
    return 0

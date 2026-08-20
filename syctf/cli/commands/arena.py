"""`syctf arena` — batch-solve a directory of challenges into a scoreboard."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def run_arena(
    path: str,
    *,
    flag_format: str | None = None,
    use_ai: bool = False,
    budget: int = 8,
    console: Console | None = None,
) -> int:
    """Solve every challenge under ``path`` and print a scoreboard."""

    console = console or Console()
    root = Path(path).expanduser()
    if not root.is_dir():
        console.print("[bold red]Arena needs a directory of challenges.[/bold red]")
        return 2

    from syctf.engine.arena import Arena

    console.print(Panel(f"🏟  Arena — sweeping [cyan]{root}[/cyan]", border_style="magenta"))
    table = Table(title="Scoreboard")
    table.add_column("Challenge", style="cyan", no_wrap=True)
    table.add_column("Category", style="white")
    table.add_column("", justify="center")
    table.add_column("Flag", style="green")

    def _row(entry) -> None:
        mark = "[green]✔[/green]" if entry.solved else "[dim]·[/dim]"
        table.add_row(entry.name, entry.category, mark, entry.flag or "[dim]—[/dim]")

    arena = Arena(use_ai=use_ai, flag_format=flag_format, budget=budget)
    result = arena.run(root, on_result=_row)

    console.print(table)
    console.print(
        f"[bold]{result.solved}/{result.total} solved[/bold] by the deterministic pass"
        + ("" if use_ai else "  [dim](add --ai for the harder ones)[/dim]")
    )
    return 0 if result.solved else 1

"""`syctf ai providers` -- show which AI backends are configured."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table


def render_providers(console: Console | None = None) -> int:
    """Render provider configuration status (no network calls)."""

    console = console or Console()
    from syctf.ai.providers import provider_status
    from syctf.ai.settings import load_ai_settings

    settings = load_ai_settings()
    table = Table(title="SYCTF AI Providers")
    table.add_column("Provider", style="cyan", no_wrap=True)
    table.add_column("Kind", style="white")
    table.add_column("Configured")
    table.add_column("Key env / local", style="yellow")
    table.add_column("Default model", style="white")

    for status in provider_status():
        ready = "[green]yes[/green]" if status.configured else "[red]no[/red]"
        where = "local" if status.local else status.env_hint
        table.add_row(status.name, status.kind, ready, where, status.default_model)

    console.print(table)
    console.print(
        f"\n[bold]Active route:[/bold] reason=[cyan]{settings.provider}:{settings.model}[/cyan] "
        f"route=[cyan]{settings.provider_for('route')}:{settings.model_for('route')}[/cyan] "
        f"code=[cyan]{settings.provider_for('code')}:{settings.model_for('code')}[/cyan]"
    )
    console.print(
        "[dim]Set SYCTF_AI_PROVIDER / SYCTF_AI_MODEL and the provider's API-key env var "
        "(see .env.example) to switch. Local Ollama needs no key.[/dim]"
    )
    return 0

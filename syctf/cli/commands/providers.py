"""`syctf ai providers` / `syctf ai use` -- show or switch AI backends."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table


def switch_provider(provider: str, model: str | None = None, console: Console | None = None) -> int:
    """Persist a provider (and optional model) switch to ai.json."""

    console = console or Console()
    from syctf.ai.providers.catalog import PROVIDERS, get_spec
    from syctf.ai.settings import load_ai_settings, save_ai_settings

    try:
        spec = get_spec(provider)
    except KeyError:
        valid = ", ".join(sorted(PROVIDERS))
        console.print(f"[red]Unknown provider {provider!r}[/red]\nValid: {valid}")
        return 1

    settings = load_ai_settings()
    settings.provider = spec.name
    settings.model = model.strip() if model else spec.model
    save_ai_settings(settings)

    key_hint = "no key needed (local)" if spec.local else f"needs ${spec.env[0]}" if spec.env else ""
    console.print(
        f"[green]Switched → [/green][cyan]{spec.name}[/cyan] / [cyan]{settings.model}[/cyan]"
        + (f"  [dim]({key_hint})[/dim]" if key_hint else "")
    )
    console.print("[dim]Saved to ~/.config/syctf/ai.json — override any time with SYCTF_AI_PROVIDER env.[/dim]")
    return 0


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

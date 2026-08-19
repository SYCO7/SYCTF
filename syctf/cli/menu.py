"""Fully menu-driven, numbered interactive interface for SYCTF.

Launch with `syctf menu` (or just `syctf` with no arguments). Everything the
toolkit can do is reachable by typing a number — categories, modules,
autonomous solve/agent, AI providers, plugins — with per-module argument
prompts. Styled with Rich; branded with the operator identity.
"""

from __future__ import annotations

import argparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from syctf.version import __release__, __version__

# Ordered main-menu actions. ("key", emoji, label, kind)
#   kind: "category" -> module picker, or a named action handled directly.
_MAIN_MENU = [
    ("solve", "🎯", "Autonomous Solve", "solve"),
    ("agent", "🤖", "Autonomous Agent (AI drives real tools)", "agent"),
    ("crypto", "🔐", "Crypto  (RSA, XOR, decode, hashes)", "category"),
    ("pwn", "💥", "Pwn  (ROP, format-string, ELF, offsets)", "category"),
    ("web", "🌐", "Web  (SQLi, XSS, LFI, JWT, recon, fuzz)", "category"),
    ("rev", "🧩", "Reverse Engineering  (triage, strings)", "category"),
    ("forensics", "🕵️", "Forensics  (stego, zip-crack, pcap)", "category"),
    ("mobile", "📱", "Mobile  (APK info, secrets, DEX)", "category"),
    ("cloud", "☁️", "Cloud  (S3, IMDS-SSRF, cloud keys)", "category"),
    ("osint", "🔎", "OSINT  (subdomains, DNS, whois, wayback)", "category"),
    ("recon", "📡", "Recon  (ports, headers, robots)", "category"),
    ("misc", "🧰", "Misc / Decode", "category"),
    ("fuzz", "🔤", "Fuzz  (wordlist mutation)", "category"),
    ("workspace", "🗂️", "Workspace", "category"),
    ("providers", "🧠", "AI Providers  (bring any key)", "providers"),
    ("ai-setup", "⚙️", "AI Setup  (local Ollama)", "ai-setup"),
    ("plugins", "🔌", "Plugins", "plugins"),
]


def _header(console: Console) -> None:
    title = Text()
    title.append("  SYCTF ", style="bold bright_green")
    title.append(f"v{__version__} ", style="bold cyan")
    title.append(f"“{__release__}”", style="bold bright_cyan")
    title.append("   ·  Autonomous, menu-driven CTF framework", style="dim")
    console.print(Panel(title, border_style="bright_cyan", padding=(0, 1)))


def _render_main_menu(console: Console) -> None:
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right", style="bold bright_cyan", no_wrap=True)
    table.add_column(style="white")
    for i, (_key, emoji, label, _kind) in enumerate(_MAIN_MENU, 1):
        table.add_row(f"[{i}]", f"{emoji}  {label}")
    table.add_row("[0]", "🚪  Exit")
    console.print(Panel(table, title="[bold bright_cyan]MAIN MENU[/bold bright_cyan]", border_style="cyan", padding=(1, 2)))


def _prompt_module_args(console: Console, plugin) -> list[str] | None:
    """Interactively collect argv for a module from its argparse spec."""

    parser = argparse.ArgumentParser(add_help=False)
    plugin.add_arguments(parser)
    positionals: list[str] = []
    options: list[str] = []
    console.print(f"[dim]Configure [/dim][bold green]{plugin.name}[/bold green][dim] — blank uses the default.[/dim]")
    for action in parser._actions:  # noqa: SLF001
        if action.dest in ("help", "_help"):
            continue
        opt = action.option_strings[0] if action.option_strings else None
        required = bool(getattr(action, "required", False))
        help_text = action.help or ""
        if action.nargs == 0:  # store_true flag
            ans = console.input(f"  [cyan]{opt}[/cyan] — {help_text} [dim](y/N)[/dim]: ").strip().lower()
            if ans in ("y", "yes", "1", "true"):
                options.append(opt)
            continue
        label = opt or f"<{action.dest}>"
        req = " [red]*required[/red]" if required else ""
        default = "" if action.default in (None, "") else f" [dim](default: {action.default})[/dim]"
        value = console.input(f"  [cyan]{label}[/cyan]{req} — {help_text}{default}: ").strip()
        if not value:
            if required:
                console.print("  [yellow]Required value missing — cancelled.[/yellow]")
                return None
            continue
        if opt:
            options += [opt, value]
        else:
            positionals.append(value)
    return positionals + options


def _run_category(app, category: str) -> None:
    console = app.console
    plugins = app.loader.discover(category)
    if not plugins:
        console.print(f"[yellow]No modules under {category}.[/yellow]")
        return

    ordered = sorted(plugins.items())
    table = Table(title=f"[bold]{category.upper()} modules[/bold]", border_style="cyan")
    table.add_column("#", style="bold bright_cyan", no_wrap=True)
    table.add_column("Module", style="green", no_wrap=True)
    table.add_column("Description", style="white")
    for i, (name, plugin) in enumerate(ordered, 1):
        table.add_row(str(i), name, getattr(plugin, "description", ""))
    console.print(table)

    choice = console.input("[bold cyan]Pick module # (or Enter to go back):[/bold cyan] ").strip()
    if not choice:
        return
    if not choice.isdigit() or not (1 <= int(choice) <= len(ordered)):
        console.print("[yellow]Invalid choice.[/yellow]")
        return

    name, plugin = ordered[int(choice) - 1]
    argv = _prompt_module_args(console, plugin)
    if argv is None:
        return

    parser = argparse.ArgumentParser(prog=name, add_help=False)
    plugin.add_arguments(parser)
    try:
        ns = parser.parse_args(argv)
    except SystemExit:
        console.print("[yellow]Argument error.[/yellow]")
        return
    console.rule(f"[bold green]running {category}/{name}[/bold green]")
    try:
        plugin.run(ns, app.context)
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted.[/yellow]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Module failed:[/bold red] {exc}")
        app.logger.exception("menu module %s/%s failed: %s", category, name, exc)


def _run_solve(app) -> None:
    console = app.console
    target = console.input("[bold cyan]Target (file / text / url / host):[/bold cyan] ").strip()
    if not target:
        return
    fmt = console.input("[cyan]Flag format[/cyan] [dim](e.g. picoCTF{}, blank=auto)[/dim]: ").strip() or None
    use_ai = console.input("[cyan]Use AI reasoning?[/cyan] [dim](Y/n)[/dim]: ").strip().lower() not in ("n", "no")
    from syctf.cli.commands.solve import run_solve

    console.rule("[bold green]autonomous solve[/bold green]")
    run_solve(target, flag_format=fmt, use_ai=use_ai, console=console)


def _run_agent(app) -> None:
    console = app.console
    target = console.input("[bold cyan]Target:[/bold cyan] ").strip()
    if not target:
        return
    goal = console.input("[cyan]Goal[/cyan] [dim](blank = capture the flag)[/dim]: ").strip() or "capture the flag"
    budget = console.input("[cyan]Max tool calls[/cyan] [dim](default 10)[/dim]: ").strip()
    from syctf.cli.commands.agent import run_agent

    console.rule("[bold green]autonomous agent[/bold green]")
    run_agent(app, target, goal=goal, budget=int(budget) if budget.isdigit() else 10)


def run_menu(app) -> int:
    """Top-level interactive numbered menu loop."""

    console: Console = app.console
    while True:
        _header(console)
        _render_main_menu(console)
        choice = console.input("[bold bright_green]syctf ▸ select #:[/bold bright_green] ").strip()

        if choice in ("0", "q", "exit", "quit"):
            console.print("[dim]bye — happy hacking.[/dim]")
            return 0
        if not choice.isdigit() or not (1 <= int(choice) <= len(_MAIN_MENU)):
            console.print("[yellow]Enter a number from the menu.[/yellow]\n")
            continue

        _key, _emoji, _label, kind = _MAIN_MENU[int(choice) - 1]
        try:
            if kind == "category":
                _run_category(app, _key)
            elif kind == "solve":
                _run_solve(app)
            elif kind == "agent":
                _run_agent(app)
            elif kind == "providers":
                from syctf.cli.commands.providers import render_providers

                render_providers(console=console)
            elif kind == "ai-setup":
                from syctf.cli.ai_setup import run_ai_setup

                try:
                    run_ai_setup(console=console, logger=app.logger)
                except TypeError:
                    run_ai_setup()
            elif kind == "plugins":
                from syctf.core.plugin_marketplace import PluginManager

                for name in PluginManager().list_plugins() or ["(none installed)"]:
                    console.print(f"  • {name}")
                console.print("[dim]Install with: syctf plugin install <git-url|name>[/dim]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled.[/yellow]")

        console.input("\n[dim]Press Enter to return to the menu…[/dim]")
        console.print()

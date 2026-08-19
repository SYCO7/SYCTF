"""Fully menu-driven, numbered interactive interface for SYCTF.

Launch with `syctf menu` (or just `syctf` with no arguments). Every capability
is reachable by number — autonomous solve/agent, all module categories, the AI
tools, and utilities — grouped and colour-coded, with per-module argument
prompts. Styled with Rich.
"""

from __future__ import annotations

import argparse

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from syctf.cli.banner import GITHUB_URL, LINKEDIN_URL, OWNER, PORTFOLIO_URL
from syctf.version import __release__, __version__

# Grouped menu:  (group title, accent style, [(label, kind), ...])
# kind: "cat:<category>" opens a module picker; anything else is a named action.
_GROUPS = [
    ("🚀  AUTONOMOUS", "bright_green", [
        ("Autonomous Solve  — ingest → tools → verified flag", "solve"),
        ("Autonomous Agent  — AI drives the real modules", "agent"),
    ]),
    ("🎯  CATEGORIES", "bright_cyan", [
        ("Crypto      — RSA · XOR · decode · hashes", "cat:crypto"),
        ("Pwn         — ROP · format-string · ELF · offsets", "cat:pwn"),
        ("Web         — SQLi · XSS · LFI · JWT", "cat:web"),
        ("Reverse     — triage · strings", "cat:rev"),
        ("Forensics   — LSB stego · zip-crack · pcap", "cat:forensics"),
        ("Mobile      — APK · AXML manifest · DEX", "cat:mobile"),
        ("Cloud       — S3 · IMDS-SSRF · cloud keys", "cat:cloud"),
        ("OSINT       — subdomains · DNS · whois · wayback", "cat:osint"),
        ("Recon       — ports · headers · robots", "cat:recon"),
        ("Fuzz        — wordlist mutation", "cat:fuzz"),
        ("Misc / Decode", "cat:misc"),
    ]),
    ("🧠  AI", "magenta", [
        ("AI Providers   — 17 backends, bring any key", "providers"),
        ("AI Setup       — local Ollama", "ai-setup"),
        ("AI Exploit     — generate an exploit skeleton", "ai-exploit"),
        ("AI Writeup     — markdown writeup from session", "ai-writeup"),
    ]),
    ("🧰  TOOLS", "yellow", [
        ("Set Flag Format  — e.g. picoCTF{}  (used by every module)", "set-format"),
        ("Auto-Decode    — multi-layer heuristic decoder", "auto-decode"),
        ("Workspace      — target / session state", "cat:workspace"),
        ("Plugins        — install & manage", "plugins"),
        ("About / Author", "about"),
    ]),
]


def _flatten():
    items: list[tuple[str, str]] = []  # (kind, label)
    layout: list[tuple] = []           # ('h', title, style) | ('r', num, label)
    n = 0
    for title, style, rows in _GROUPS:
        layout.append(("h", title, style))
        for label, kind in rows:
            n += 1
            items.append((kind, label))
            layout.append(("r", n, label))
    return items, layout


_ITEMS, _LAYOUT = _flatten()


def _header(app) -> None:
    console = app.console
    fmt = app.context.cache.get("flag_format") or "auto-detect"
    title = Text()
    title.append(" SYCTF ", style="bold bright_green")
    title.append(f"v{__version__} ", style="bold cyan")
    title.append(f"“{__release__}”", style="bold bright_cyan")
    title.append("   ·  flag format: ", style="dim")
    title.append(fmt, style="bold yellow")
    console.print(Panel(title, border_style="bright_cyan", padding=(0, 1)))


def _ask_flag_format(app, *, required: bool = False) -> str | None:
    """Prompt for the challenge flag format; persist it for every module."""

    console = app.console
    current = app.context.cache.get("flag_format")
    hint = f" [dim](current: {current})[/dim]" if current else " [dim](e.g. picoCTF, HTB, flag — blank = auto)[/dim]"
    value = console.input(f"[bold cyan]Flag format{hint}:[/bold cyan] ").strip()
    if not value:
        if required and not current:
            console.print("[yellow]No format set — using auto-detect.[/yellow]")
        return current
    app.context.cache["flag_format"] = value
    console.print(f"[green]Flag format set:[/green] {value}")
    return value


def _render_menu(console: Console) -> None:
    body: list = []
    for entry in _LAYOUT:
        if entry[0] == "h":
            body.append(Text(f"\n{entry[1]}", style=f"bold {entry[2]}"))
        else:
            _, num, label = entry
            line = Text()
            line.append(f"  [{num:>2}] ", style="bold bright_cyan")
            line.append(label, style="white")
            body.append(line)
    body.append(Text("\n  [ 0] ", style="bold red").append("Exit", style="bold white"))
    console.print(Panel(Group(*body), title="[bold bright_cyan]MAIN MENU[/bold bright_cyan]", border_style="cyan", padding=(1, 2)))


def _prompt_module_args(console: Console, plugin) -> list[str] | None:
    parser = argparse.ArgumentParser(add_help=False)
    plugin.add_arguments(parser)
    positionals: list[str] = []
    options: list[str] = []
    console.print(f"[dim]Configure [/dim][bold green]{plugin.name}[/bold green][dim] — blank = default.[/dim]")
    for action in parser._actions:  # noqa: SLF001
        if action.dest in ("help", "_help"):
            continue
        opt = action.option_strings[0] if action.option_strings else None
        required = bool(getattr(action, "required", False))
        help_text = action.help or ""
        if action.nargs == 0:
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
        (options.extend([opt, value]) if opt else positionals.append(value))
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

    choice = console.input("[bold cyan]Pick module # (Enter = back):[/bold cyan] ").strip()
    if not choice or not choice.isdigit() or not (1 <= int(choice) <= len(ordered)):
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
    fmt = _ask_flag_format(app, required=True)          # challenge start: user gives the format
    target = console.input("[bold cyan]Target (file / text / url / host):[/bold cyan] ").strip()
    if not target:
        return
    use_ai = console.input("[cyan]Use AI reasoning?[/cyan] [dim](Y/n)[/dim]: ").strip().lower() not in ("n", "no")
    from syctf.cli.commands.solve import run_solve

    console.rule("[bold green]autonomous solve[/bold green]")
    run_solve(target, flag_format=fmt, use_ai=use_ai, console=console)


def _run_agent(app) -> None:
    console = app.console
    fmt = _ask_flag_format(app, required=True)          # challenge start: user gives the format
    target = console.input("[bold cyan]Target:[/bold cyan] ").strip()
    if not target:
        return
    goal = console.input("[cyan]Goal[/cyan] [dim](blank = capture the flag)[/dim]: ").strip() or "capture the flag"
    budget = console.input("[cyan]Max tool calls[/cyan] [dim](default 10)[/dim]: ").strip()
    from syctf.cli.commands.agent import run_agent

    console.rule("[bold green]autonomous agent[/bold green]")
    run_agent(app, target, goal=goal, budget=int(budget) if budget.isdigit() else 10, flag_format=fmt)


def _run_auto_decode(app) -> None:
    console = app.console
    cipher = console.input("[bold cyan]Ciphertext to decode:[/bold cyan] ").strip()
    if not cipher:
        return
    script = console.input("[cyan]Emit reproducer script?[/cyan] [dim](y/N)[/dim]: ").strip().lower() in ("y", "yes")
    from syctf.modules.ai.auto_decode import run_auto_decode_command

    console.rule("[bold green]auto-decode[/bold green]")
    try:
        run_auto_decode_command(cipher, console=console, cache=app.context.cache, script=script)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Auto-decode failed:[/bold red] {exc}")


def _run_ai_exploit(app) -> None:
    console = app.console
    binary = console.input("[bold cyan]Path to ELF binary:[/bold cyan] ").strip()
    if not binary:
        return
    remote = console.input("[cyan]Remote host:port[/cyan] [dim](blank = none)[/dim]: ").strip() or None
    from syctf.modules.ai.exploit_generator import generate_exploit

    console.rule("[bold green]AI exploit skeleton[/bold green]")
    try:
        generate_exploit(binary, remote=remote, workspace_root=app.context.cache.get("workspace_root"),
                         console=console, cache=app.context.cache)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Exploit generation failed:[/bold red] {exc}")


def _run_ai_writeup(app) -> None:
    console = app.console
    from syctf.modules.ai.writeup_generator import generate_writeup

    console.rule("[bold green]AI writeup[/bold green]")
    try:
        generate_writeup(cache=app.context.cache, console=console)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Writeup failed:[/bold red] {exc}")


def _about(console: Console) -> None:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold green", justify="right")
    grid.add_column(style="white")
    grid.add_row("Tool", f"SYCTF v{__version__} “{__release__}”")
    grid.add_row("Author", f"[bold white]{OWNER}[/bold white]")
    grid.add_row("GitHub", f"[link={GITHUB_URL}]{GITHUB_URL}[/link]")
    grid.add_row("LinkedIn", f"[link={LINKEDIN_URL}]{LINKEDIN_URL}[/link]")
    grid.add_row("Portfolio", f"[link={PORTFOLIO_URL}]{PORTFOLIO_URL}[/link]")
    console.print(Panel(grid, title="[bold bright_cyan]About SYCTF[/bold bright_cyan]", border_style="bright_cyan", padding=(1, 2)))


def _plugins(console: Console) -> None:
    from syctf.core.plugin_marketplace import PluginManager

    for name in PluginManager().list_plugins() or ["(none installed)"]:
        console.print(f"  • {name}")
    console.print("[dim]Install: syctf plugin install <git-url | name>[/dim]")


def run_menu(app) -> int:
    """Top-level interactive numbered menu loop."""

    console: Console = app.console
    while True:
        _header(app)
        _render_menu(console)
        choice = console.input("[bold bright_green]syctf ▸ select #:[/bold bright_green] ").strip().lower()

        if choice in ("0", "q", "exit", "quit"):
            console.print("[dim]bye — happy hacking.[/dim]")
            return 0
        if not choice.isdigit() or not (1 <= int(choice) <= len(_ITEMS)):
            console.print("[yellow]Enter a number from the menu.[/yellow]\n")
            continue

        kind, _label = _ITEMS[int(choice) - 1]
        try:
            if kind.startswith("cat:"):
                _run_category(app, kind.split(":", 1)[1])
            elif kind == "solve":
                _run_solve(app)
            elif kind == "agent":
                _run_agent(app)
            elif kind == "set-format":
                _ask_flag_format(app)
            elif kind == "auto-decode":
                _run_auto_decode(app)
            elif kind == "ai-exploit":
                _run_ai_exploit(app)
            elif kind == "ai-writeup":
                _run_ai_writeup(app)
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
                _plugins(console)
            elif kind == "about":
                _about(console)
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled.[/yellow]")

        console.input("\n[dim]Press Enter to return to the menu…[/dim]")
        console.print()

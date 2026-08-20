"""Fully menu-driven, numbered interactive interface for SYCTF.

Short main menu + submenus so the banner stays on screen. Launch with
`syctf menu`, or just `syctf` with no arguments. Every capability is reachable
by number, with per-module argument prompts. Styled with Rich.
"""

from __future__ import annotations

import argparse

from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from syctf.cli.banner import ASCII_LOGO, GITHUB_URL, LINKEDIN_URL, OWNER, _build_logo
from syctf.version import __release__, __version__

# --- short main menu (no emoji: many terminals render them as broken glyphs) --
_MAIN = [
    ("", "Autonomous Solve", "solve"),
    ("", "Autonomous Agent", "agent"),
    ("", "Arena — sweep a whole folder", "arena"),
    ("", "Categories  >", "sub:categories"),
    ("", "AI & Providers  >", "sub:ai"),
    ("", "Tools & Settings  >", "sub:tools"),
]

# --- submenus ----------------------------------------------------------------
_CATEGORIES = [
    ("crypto", "Crypto      — RSA · XOR · decode · hashes"),
    ("pwn", "Pwn         — ROP · heap · fmtstr · ELF"),
    ("web", "Web         — SQLi · XSS · LFI · JWT"),
    ("rev", "Reverse     — triage · strings"),
    ("forensics", "Forensics   — stego · audio · git · metadata · pcap · zip"),
    ("mobile", "Mobile      — APK · AXML · DEX"),
    ("cloud", "Cloud       — S3 · IMDS-SSRF · keys"),
    ("osint", "OSINT       — subdomains · DNS · whois · wayback"),
    ("recon", "Recon       — ports · headers · robots"),
    ("fuzz", "Fuzz        — wordlist mutation"),
    ("workspace", "Workspace   — target / session state"),
    ("misc", "Misc / Decode"),
]
_AI = [
    ("set-key", "Set AI Key     — pick provider + paste key (saved & activated)"),
    ("providers", "AI Providers   — 17 backends, bring any key"),
    ("ai-setup", "AI Setup       — local Ollama"),
    ("ai-exploit", "AI Exploit     — generate exploit skeleton"),
    ("ai-writeup", "AI Writeup     — markdown from session"),
]
_TOOLS = [
    ("set-format", "Set Flag Format  — e.g. picoCTF  (used by every module)"),
    ("auto-decode", "Auto-Decode      — multi-layer heuristic decoder"),
    ("memory", "Solve Memory     — techniques learned across challenges"),
    ("plugins", "Plugins          — install & manage"),
    ("about", "About"),
]


def _header(app) -> None:
    fmt = app.context.cache.get("flag_format") or "auto-detect"
    logo = _build_logo(ASCII_LOGO[:6])          # the SYCTF lettering (no tagline)
    sub = Text()
    sub.append(f"v{__version__} “{__release__}”", style="bold bright_cyan")
    sub.append("    ·    flag format: ", style="dim")
    sub.append(fmt, style="bold yellow")
    app.console.print(
        Panel(Group(Align.center(logo), Align.center(sub)), border_style="bright_cyan", padding=(0, 1))
    )


def _render(console: Console, title: str, rows: list, *, back: bool = False) -> None:
    body: list = []
    for i, (icon, label) in enumerate(rows, 1):
        line = Text()
        line.append(f"  [{i:>2}] ", style="bold bright_cyan")
        if icon:
            line.append(f"{icon}  ", style="white")
        line.append(label, style="white")
        body.append(line)
    tail = Text("\n  [ 0] ", style="bold red")
    tail.append("Back" if back else "Exit", style="bold white")
    body.append(tail)
    console.print(Panel(Group(*body), title=f"[bold bright_cyan]{title}[/bold bright_cyan]", border_style="cyan", padding=(1, 2)))


def _ask_flag_format(app, *, required: bool = False) -> str | None:
    console = app.console
    current = app.context.cache.get("flag_format")
    hint = f" [dim](current: {current})[/dim]" if current else " [dim](e.g. picoCTF, HTB, flag — blank = auto)[/dim]"
    value = console.input(f"[bold cyan]Flag format{hint}:[/bold cyan] ").strip()
    if not value:
        return current
    app.context.cache["flag_format"] = value
    console.print(f"[green]Flag format set:[/green] {value}")
    return value


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
    fmt = _ask_flag_format(app, required=True)
    target = console.input("[bold cyan]Target (file / text / url / host):[/bold cyan] ").strip()
    if not target:
        return
    use_ai = console.input("[cyan]Use AI reasoning?[/cyan] [dim](Y/n)[/dim]: ").strip().lower() not in ("n", "no")
    from syctf.cli.commands.solve import run_solve

    console.rule("[bold green]autonomous solve[/bold green]")
    run_solve(target, flag_format=fmt, use_ai=use_ai, console=console)


def _run_agent(app) -> None:
    console = app.console
    fmt = _ask_flag_format(app, required=True)
    target = console.input("[bold cyan]Target:[/bold cyan] ").strip()
    if not target:
        return
    goal = console.input("[cyan]Goal[/cyan] [dim](blank = capture the flag)[/dim]: ").strip() or "capture the flag"
    budget = console.input("[cyan]Max tool calls[/cyan] [dim](default 10)[/dim]: ").strip()
    from syctf.cli.commands.agent import run_agent

    console.rule("[bold green]autonomous agent[/bold green]")
    run_agent(app, target, goal=goal, budget=int(budget) if budget.isdigit() else 10, flag_format=fmt)


def _run_arena(app) -> None:
    console = app.console
    fmt = _ask_flag_format(app)
    path = console.input("[bold cyan]Folder of challenges:[/bold cyan] ").strip()
    if not path:
        return
    use_ai = console.input("[cyan]Use AI per challenge?[/cyan] [dim](y/N)[/dim]: ").strip().lower() in ("y", "yes")
    from syctf.cli.commands.arena import run_arena

    console.rule("[bold green]arena[/bold green]")
    run_arena(path, flag_format=fmt, use_ai=use_ai, console=console)


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
    console.print(Panel(grid, title="[bold bright_cyan]About[/bold bright_cyan]", border_style="bright_cyan", padding=(1, 2)))


def _set_ai_key(app) -> None:
    """Pick a provider, paste its key (hidden), and activate it — no shell needed."""

    console = app.console
    from syctf.ai.keystore import set_key
    from syctf.ai.providers.catalog import PROVIDERS
    from syctf.ai.settings import load_ai_settings, save_ai_settings

    specs = list(PROVIDERS.values())
    table = Table(title="Choose a provider", border_style="cyan")
    table.add_column("#", style="bold bright_cyan", no_wrap=True)
    table.add_column("Provider", style="green")
    table.add_column("Default model", style="white")
    table.add_column("", style="dim")
    for i, spec in enumerate(specs, 1):
        table.add_row(str(i), spec.name, spec.model, "local (no key)" if spec.local else spec.env[0] if spec.env else "")
    console.print(table)

    choice = console.input("[bold cyan]Provider # (Enter = cancel):[/bold cyan] ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(specs)):
        return
    spec = specs[int(choice) - 1]

    if not spec.local:
        key = console.input(f"[bold cyan]Paste {spec.name} API key[/bold cyan] [dim](hidden)[/dim]: ", password=True).strip()
        if key:
            set_key(spec.name, key)
            console.print(f"[green]Key saved for {spec.name}[/green] [dim](~/.config/syctf/keys.json, 0600)[/dim]")
    model = console.input(f"[cyan]Model[/cyan] [dim](Enter = {spec.model})[/dim]: ").strip() or spec.model

    settings = load_ai_settings()
    settings.provider = spec.name
    settings.model = model
    save_ai_settings(settings)
    console.print(f"[bold green]Active AI:[/bold green] {spec.name} · {model}")
    console.print("[dim]Verify from the menu → AI Providers.[/dim]")


def _plugins(console: Console) -> None:
    from syctf.core.plugin_marketplace import PluginManager

    for name in PluginManager().list_plugins() or ["(none installed)"]:
        console.print(f"  • {name}")
    console.print("[dim]Install: syctf plugin install <git-url | name>[/dim]")


def _dispatch(app, kind: str) -> None:
    console = app.console
    if kind == "solve":
        _run_solve(app)
    elif kind == "agent":
        _run_agent(app)
    elif kind == "arena":
        _run_arena(app)
    elif kind == "auto-decode":
        _run_auto_decode(app)
    elif kind == "ai-exploit":
        _run_ai_exploit(app)
    elif kind == "ai-writeup":
        _run_ai_writeup(app)
    elif kind == "set-format":
        _ask_flag_format(app)
    elif kind == "memory":
        from syctf.cli.commands.memory import render_memory

        render_memory(console=console)
    elif kind == "set-key":
        _set_ai_key(app)
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


def _submenu(app, title: str, items: list[tuple[str, str]], *, is_category: bool) -> None:
    console = app.console
    rows = [("", label) for _key, label in items]
    while True:
        console.clear()
        _header(app)
        _render(console, title, rows, back=True)
        choice = console.input("[bold bright_green]▸ select # (0 = back):[/bold bright_green] ").strip()
        if choice in ("0", "", "b", "back"):
            return
        if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
            console.print("[yellow]Enter a number from the list.[/yellow]\n")
            continue
        key = items[int(choice) - 1][0]
        try:
            if is_category:
                _run_category(app, key)
            else:
                _dispatch(app, key)
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled.[/yellow]")
        console.input("\n[dim]Press Enter…[/dim]")
        console.print()


def run_menu(app) -> int:
    """Top-level interactive numbered menu loop."""

    console: Console = app.console
    main_rows = [(icon, label) for icon, label, _kind in _MAIN]
    while True:
        console.clear()
        _header(app)
        _render(console, "MAIN MENU", main_rows)
        choice = console.input("[bold bright_green]syctf ▸ select #:[/bold bright_green] ").strip().lower()

        if choice in ("0", "q", "exit", "quit"):
            console.print("[dim]bye — happy hacking.[/dim]")
            return 0
        if not choice.isdigit() or not (1 <= int(choice) <= len(_MAIN)):
            console.print("[yellow]Enter a number from the menu.[/yellow]\n")
            continue

        kind = _MAIN[int(choice) - 1][2]
        if kind == "sub:categories":
            _submenu(app, "CATEGORIES", _CATEGORIES, is_category=True)
            continue
        if kind == "sub:ai":
            _submenu(app, "AI & PROVIDERS", _AI, is_category=False)
            continue
        if kind == "sub:tools":
            _submenu(app, "TOOLS & SETTINGS", _TOOLS, is_category=False)
            continue

        try:
            _dispatch(app, kind)
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled.[/yellow]")
        console.input("\n[dim]Press Enter to return to the menu…[/dim]")
        console.print()

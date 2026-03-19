"""Interactive shell mode for SYCTF."""

from __future__ import annotations

import argparse
import importlib
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.table import Table


@dataclass
class ShellState:
    """Holds current shell state for active module and options."""

    active_key: str | None = None
    options: dict[str, str] = field(default_factory=dict)


@dataclass
class ModuleRecord:
    """Describes one discovered executable module."""

    key: str
    category: str
    name: str
    description: str
    plugin: Any


def _discover_categories(app) -> list[str]:
    """Discover module categories by scanning configured module roots."""

    categories: set[str] = set()
    for root in getattr(app.loader, "modules_roots", []):
        root_path = Path(root)
        if not root_path.exists() or not root_path.is_dir():
            continue
        for child in root_path.iterdir():
            if child.is_dir() and not child.name.startswith("__"):
                categories.add(child.name)
    return sorted(categories)


def _build_registry(app) -> dict[str, ModuleRecord]:
    """Build module registry from modules/<category>/*.py via PluginLoader."""

    registry: dict[str, ModuleRecord] = {}
    for category in _discover_categories(app):
        for plugin in app.loader.discover(category).values():
            key = f"{category}/{plugin.name}"
            registry[key] = ModuleRecord(
                key=key,
                category=category,
                name=plugin.name,
                description=str(getattr(plugin, "description", "")),
                plugin=plugin,
            )
    return registry


def _render_list(app, registry: dict[str, ModuleRecord]) -> None:
    """Render grouped module list table."""

    if not registry:
        app.console.print("[yellow]No modules discovered.[/yellow]")
        return

    table = Table(title="SYCTF Modules")
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Module", style="green", no_wrap=True)
    table.add_column("Description", style="white")

    for key in sorted(registry.keys()):
        item = registry[key]
        table.add_row(item.category, item.name, item.description)
    app.console.print(table)


def _module_parser(record: ModuleRecord) -> argparse.ArgumentParser:
    """Create argparse parser for one module run/info inspection."""

    parser = argparse.ArgumentParser(prog=record.name, add_help=False)
    parser.add_argument("-h", "--help", action="store_true", dest="_help")
    add_arguments = getattr(record.plugin, "add_arguments", None)
    if callable(add_arguments):
        add_arguments(parser)
    return parser


def _usage_example(parser: argparse.ArgumentParser) -> str:
    """Build simple example usage from parser actions."""

    parts: list[str] = ["run"]
    for action in parser._actions:  # noqa: SLF001
        if action.dest in {"_help", "help"}:
            continue
        if not action.option_strings and action.dest:
            parts.append(f"<{action.dest}>")
            continue
        if action.option_strings:
            opt = action.option_strings[0]
            if action.nargs == 0:
                parts.append(opt)
            else:
                parts.append(f"{opt} <{action.dest}>")
    return " ".join(parts)


def _render_info(app, record: ModuleRecord) -> None:
    """Render active module information and argument expectations."""

    parser = _module_parser(record)
    args_table = Table(title=f"Module Info: {record.key}")
    args_table.add_column("Field", style="cyan", no_wrap=True)
    args_table.add_column("Value", style="white")
    args_table.add_row("Description", record.description or "(no description)")

    expected: list[str] = []
    for action in parser._actions:  # noqa: SLF001
        if action.dest in {"_help", "help"}:
            continue
        if action.option_strings:
            expected.append(f"{action.option_strings[0]} ({action.dest})")
        else:
            expected.append(f"{action.dest} (positional)")
    args_table.add_row("Expected Arguments", ", ".join(expected) if expected else "none")
    args_table.add_row("Example", _usage_example(parser))
    app.console.print(args_table)


def _apply_set_options(raw_args: list[str], options: dict[str, str]) -> list[str]:
    """Apply set options as optional flags if not already present in raw args."""

    provided_options = {token for token in raw_args if token.startswith("--")}
    merged = list(raw_args)
    for key, value in options.items():
        flag = f"--{key}"
        if flag in provided_options:
            continue
        merged.extend([flag, value])
    return merged


def _run_active_module(app, state: ShellState, registry: dict[str, ModuleRecord], run_line: str) -> None:
    """Run selected module with provided run arguments and set-options fallback."""

    if not state.active_key or state.active_key not in registry:
        app.console.print("[yellow]No active module. Use: use <category/module>[/yellow]")
        return

    record = registry[state.active_key]
    parser = _module_parser(record)
    raw_args = shlex.split(run_line) if run_line.strip() else []
    candidate_args = _apply_set_options(raw_args, state.options)

    try:
        parsed = parser.parse_args(candidate_args)
    except SystemExit:
        app.console.print(f"[yellow]Usage:[/yellow] {_usage_example(parser)}")
        return

    if getattr(parsed, "_help", False):
        app.console.print(f"[yellow]Usage:[/yellow] {_usage_example(parser)}")
        return

    try:
        record.plugin.run(parsed, app.context)
    except KeyboardInterrupt:
        app.console.print("[yellow]Module execution interrupted by user.[/yellow]")
    except Exception as exc:  # noqa: BLE001
        app.console.print(f"[bold red]Module run failed:[/bold red] {exc}")
        app.logger.exception("module run failure key=%s err=%s", record.key, exc)


def run_shell(app) -> int:
    """Run interactive command loop until user exits."""

    AISession = importlib.import_module("syctf.modules.ai.session").AISession
    ai_session = AISession(
        console=app.console,
        app_logger=app.logger,
        execution_context=app.context,
        plugin_loader=app.loader,
        ai_auto_run=bool(getattr(app.config, "ai_auto_run", True)),
    )
    registry = _build_registry(app)
    state = ShellState()

    app.console.print("[bold green]SYCTF interactive shell started.[/bold green]")
    app.console.print(
        "Type 'help' for shell help, 'list' to browse modules, 'exit' to quit, 'ai' for AI mode.\n"
    )

    while True:
        prompt = "SYCTF > " if not state.active_key else f"SYCTF ({state.active_key.split('/')[-1]}) > "
        try:
            cmd = input(prompt).strip()
        except EOFError:
            app.console.print()
            return 0

        if not cmd:
            continue

        history = app.context.cache.setdefault("command_history", [])
        if isinstance(history, list):
            history.append(cmd)
            if len(history) > 200:
                del history[: len(history) - 200]

        lowered = cmd.lower()
        if lowered in {"exit", "quit"}:
            return 0

        if lowered == "help":
            app.console.print(
                Panel(
                    "[bold cyan]Shell commands[/bold cyan]\n"
                    "list              List available modules\n"
                    "use <cat/mod>     Select active module\n"
                    "info              Show active module info\n"
                    "set <k> <v>       Store reusable module option\n"
                    "run <args>        Run active module\n"
                    "back              Unset active module\n"
                    "ai                Enter AI chat mode\n"
                    "ai exploit <path> Generate exploit skeleton for ELF binary\n"
                    "ai writeup        Generate markdown writeup from session context\n"
                    "ai decode         Enter AI decoding mode\n"
                    "ai recon-plan     Enter AI recon planning mode\n"
                    "auto-decode ...   Forward to top-level auto decode command\n"
                    "help              Show this panel\n"
                    "exit              Exit shell\n\n"
                    "Other input is forwarded to standard SYCTF argparse commands.",
                    title="SYCTF Shell Help",
                    border_style="cyan",
                )
            )
            app.parser.print_help()
            continue

        if lowered == "list":
            _render_list(app, registry)
            continue

        if lowered.startswith("use "):
            target = cmd.split(maxsplit=1)[1].strip()
            record = registry.get(target)
            if record is None:
                app.console.print(f"[bold red]Unknown module:[/bold red] {target}")
                app.console.print("[yellow]Hint:[/yellow] run 'list' to see available modules")
                continue
            state.active_key = target
            state.options.clear()
            app.console.print(f"[green]Active module set:[/green] {target}")
            continue

        if lowered == "info":
            if not state.active_key or state.active_key not in registry:
                app.console.print("[yellow]No active module. Use: use <category/module>[/yellow]")
                continue
            _render_info(app, registry[state.active_key])
            continue

        if lowered.startswith("set "):
            parts = cmd.split(maxsplit=2)
            if len(parts) < 3:
                app.console.print("[yellow]Usage:[/yellow] set <key> <value>")
                continue
            key = parts[1].strip().lstrip("-")
            value = parts[2].strip()
            if not key or not value:
                app.console.print("[yellow]Usage:[/yellow] set <key> <value>")
                continue
            state.options[key] = value
            if key.lower() == "target":
                app.context.cache["target"] = value
            app.console.print(f"[green]Option set:[/green] {key}={value}")
            continue

        if lowered.startswith("run"):
            run_line = cmd[3:].strip() if len(cmd) > 3 else ""
            _run_active_module(app, state, registry, run_line)
            continue

        if lowered == "back":
            state.active_key = None
            state.options.clear()
            app.console.print("[green]Returned to main shell.[/green]")
            continue

        if lowered.startswith("ai"):
            # First-class shell command routing, not argparse command registration.
            try:
                parts = shlex.split(cmd)
            except ValueError as exc:
                app.console.print(f"[bold red]Parse error:[/bold red] {exc}")
                continue

            if len(parts) >= 3 and parts[1].lower() == "exploit":
                binary_path = parts[2].strip()
                remote = None
                if len(parts) > 3:
                    if len(parts) == 5 and parts[3] == "--remote":
                        remote = parts[4].strip()
                    else:
                        app.console.print(
                            "[yellow]Usage:[/yellow] ai exploit <binary_path> [--remote host:port]"
                        )
                        continue
                ai_session.run_exploit_mode(binary_path, remote=remote)
                continue

            if len(parts) >= 2 and parts[1].lower() == "writeup":
                generate_writeup = importlib.import_module("syctf.modules.ai.writeup_generator").generate_writeup
                model = "deepseek-coder:6.7b"
                if len(parts) > 2:
                    if len(parts) == 4 and parts[2] == "--model":
                        model = parts[3].strip() or model
                    else:
                        app.console.print("[yellow]Usage:[/yellow] ai writeup [--model <model_name>]")
                        continue

                try:
                    generate_writeup(cache=app.context.cache, console=app.console, model=model)
                except Exception as exc:  # noqa: BLE001
                    app.console.print(f"[bold red]AI writeup failed:[/bold red] {exc}")
                    app.logger.exception("ai writeup generation failed: %s", exc)
                continue

            mode = "chat"
            if len(parts) == 2 and parts[1].strip():
                mode = parts[1].strip().lower()
            ai_session.start(mode=mode)
            continue

        try:
            tokens = shlex.split(cmd)
        except ValueError as exc:
            app.console.print(f"[bold red]Parse error:[/bold red] {exc}")
            continue

        if "--no-banner" not in tokens:
            tokens.insert(0, "--no-banner")

        try:
            args = app.parser.parse_args(tokens)
        except SystemExit:
            continue

        if args.command == "shell":
            app.console.print("[yellow]Already in shell mode.[/yellow]")
            continue

        app.execute_parsed(args)

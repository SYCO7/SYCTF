"""Benchmark helpers for runtime and module execution timing."""

from __future__ import annotations

import argparse
import time
from typing import Any

from rich.table import Table


def run_benchmark(app, args: Any) -> int:
    """Measure startup time and one lazy-loaded module execution."""

    category = str(getattr(args, "category", "misc")).strip() or "misc"
    module_name = str(getattr(args, "module", "env-check")).strip() or "env-check"
    module_args = list(getattr(args, "module_args", []) or [])

    startup_ms = float(getattr(app, "startup_time_ms", 0.0))

    discover_started = time.perf_counter()
    plugins = app.loader.discover(category)
    discover_ms = (time.perf_counter() - discover_started) * 1000.0

    if not plugins:
        app.console.print(f"[yellow]No plugins discovered under category '{category}'.[/yellow]")
        return 1

    plugin = plugins.get(module_name)
    if plugin is None:
        available = ", ".join(sorted(plugins.keys())[:20])
        app.console.print(f"[yellow]Module not found:[/yellow] {category}/{module_name}")
        app.console.print(f"[cyan]Available:[/cyan] {available}")
        return 1

    parser = argparse.ArgumentParser(prog=f"bench {category} {module_name}", add_help=False)
    parser.add_argument("-h", "--help", action="store_true", dest="_help")
    plugin.add_arguments(parser)

    try:
        parsed = parser.parse_args(module_args)
    except SystemExit:
        app.console.print("[yellow]Module args parse failed in bench mode.[/yellow]")
        return 1

    exec_started = time.perf_counter()
    try:
        code = plugin.run(parsed, app.context)
        exit_code = int(code) if isinstance(code, int) else 0
    except Exception as exc:  # noqa: BLE001
        app.console.print(f"[bold red]Benchmark module run failed:[/bold red] {exc}")
        app.logger.exception("bench module failure %s/%s: %s", category, module_name, exc)
        return 1
    exec_ms = (time.perf_counter() - exec_started) * 1000.0

    table = Table(title="SYCTF Benchmark")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")
    table.add_row("Startup Time", f"{startup_ms:.2f} ms")
    table.add_row("Plugin Discover Time", f"{discover_ms:.2f} ms")
    table.add_row("Module Execution Time", f"{exec_ms:.2f} ms")
    table.add_row("Bench Target", f"{category}/{module_name}")
    table.add_row("Module Exit Code", str(exit_code))
    app.console.print(table)
    return 0 if exit_code == 0 else 1

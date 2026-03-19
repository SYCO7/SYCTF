"""Primary CLI bootstrap for SYCTF."""

from __future__ import annotations

import sys
import time

from colorama import just_fix_windows_console
from rich.console import Console

from syctf.cli.app import SyctfApp
from syctf.cli.ai_setup import run_ai_setup
from syctf.core.config import load_config
from syctf.core.execution import run_with_guard
from syctf.core.logging_setup import configure_logging
from syctf.core.paths import get_config_file_path, get_logs_dir


def _dispatch(argv: list[str], app: SyctfApp, console: Console, logger) -> int:
	"""Dispatch command execution with explicit ai-setup failure safety."""

	command = ""
	for token in argv:
		if token.startswith("-"):
			continue
		command = token
		break

	if command == "ai-setup":
		try:
			# Keep compatibility with both run_ai_setup() and run_ai_setup(console=..., logger=...).
			try:
				result = run_ai_setup(console=console, logger=logger)
			except TypeError:
				result = run_ai_setup()
			return int(result) if isinstance(result, int) else 0
		except Exception as exc:  # noqa: BLE001
			console.print(f"[bold red]AI setup failed:[/bold red] {exc}")
			logger.exception("ai-setup crashed: %s", exc)
			return 1

	return app.run(argv)


def main() -> int:
	"""Initialize runtime services and execute the CLI."""

	started = time.perf_counter()
	just_fix_windows_console()
	console = Console()
	config = load_config(get_config_file_path())
	logger = configure_logging(get_logs_dir() / "syctf.log")
	argv = sys.argv[1:]

	startup_time_ms = (time.perf_counter() - started) * 1000.0
	app = SyctfApp(config=config, logger=logger, console=console, startup_time_ms=startup_time_ms)
	return run_with_guard(
		lambda: _dispatch(argv, app, console, logger),
		console=console,
		logger_name="main",
		logger=logger,
	)


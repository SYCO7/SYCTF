"""CLI orchestration logic for SYCTF."""

from __future__ import annotations

import argparse
import importlib
from pathlib import Path
from typing import Any

from rich.console import Console

from syctf.cli.ai_setup import run_ai_setup
from syctf.cli.banner import render_startup
from syctf.cli.shell import run_shell
from syctf.core.benchmark import run_benchmark
from syctf.core.execution import run_with_guard
from syctf.core.plugin_marketplace import PluginManager, run_plugin_command
from syctf.core.plugin_loader import PluginLoader
from syctf.core.types import AppConfig, ExecutionContext
from syctf.core.workspace_state import apply_state_to_cache
from syctf import modules

COMMAND_CATEGORY_MAP: dict[str, str] = {
	"recon": "recon",
	"fuzz": "fuzz",
	"encode": "crypto",
	"decode": "crypto",
	"pwn-helper": "pwn",
	"web-helper": "web",
	"rev-helper": "rev",
	"workspace": "workspace",
	"crypto-helper": "crypto",
	"misc": "misc",
}


class SyctfApp:
	"""Main application object for parser, context, and command execution."""

	def __init__(self, config: AppConfig, logger, console: Console, *, startup_time_ms: float = 0.0) -> None:
		self.config = config
		self.logger = logger
		self.console = console
		self.startup_time_ms = float(startup_time_ms)
		self.plugin_manager = PluginManager()
		for warning in self.plugin_manager.compatibility_warnings():
			self.logger.warning("plugin compatibility warning: %s", warning)
			self.console.print(f"[yellow]Plugin compatibility warning:[/yellow] {warning}")
		modules_root = Path(modules.__file__).resolve().parent
		plugin_roots = self.plugin_manager.discover_module_roots()
		self.loader = PluginLoader(modules_roots=[modules_root, *plugin_roots], logger=logger)
		self.context = ExecutionContext(
			config=config,
			logger=logger,
			console=console,
			plugin_loader=self.loader,
		)
		apply_state_to_cache(self.context.cache)
		self.parser = self._build_parser()

	def run(self, argv: list[str]) -> int:
		"""Run the CLI with an argument vector."""

		history = self.context.cache.setdefault("command_history", [])
		if isinstance(history, list):
			history.append("syctf " + " ".join(argv))
			if len(history) > 200:
				del history[: len(history) - 200]

		args = self.parser.parse_args(argv)
		if not args.no_banner:
			render_startup(self.console)

		if args.command == "shell":
			return run_shell(self)

		if args.command == "ai-setup":
			try:
				result = run_ai_setup(console=self.console, logger=self.logger)
			except TypeError:
				result = run_ai_setup()
			return int(result) if isinstance(result, int) else 0

		if args.command == "plugin":
			return run_plugin_command(args, console=self.console, logger=self.logger)

		if args.command == "bench":
			return run_benchmark(self, args)

		if args.command == "ai":
			if getattr(args, "ai_action", "") == "exploit":
				generate_exploit = importlib.import_module("syctf.modules.ai.exploit_generator").generate_exploit
				return run_with_guard(
					lambda: (
						generate_exploit(
							args.binary_path,
							remote=getattr(args, "remote", None),
							workspace_root=self.context.cache.get("workspace_root"),
							console=self.console,
							cache=self.context.cache,
						),
						0,
					)[1],
					console=self.console,
					logger_name="ai:exploit",
					logger=self.logger,
				)
			if getattr(args, "ai_action", "") == "writeup":
				generate_writeup = importlib.import_module("syctf.modules.ai.writeup_generator").generate_writeup
				return run_with_guard(
					lambda: (
						generate_writeup(
							cache=self.context.cache,
							console=self.console,
							model=getattr(args, "model", "deepseek-coder:6.7b"),
						),
						0,
					)[1],
					console=self.console,
					logger_name="ai:writeup",
					logger=self.logger,
				)
			self.console.print("[yellow]Usage:[/yellow] syctf ai exploit <binary_path> | syctf ai writeup")
			return 2

		if not args.command:
			self.parser.print_help()
			return 0

		return self.execute_parsed(args)

	def execute_parsed(self, args: Any) -> int:
		"""Execute already parsed command arguments."""

		category = getattr(args, "_category", None)
		if not category:
			self.console.print("[bold red]Unknown command category.[/bold red]")
			return 2

		plugins = self.loader.discover(str(category))
		if not plugins:
			self.console.print(
				f"[yellow]No modules discovered under modules/{category}[/yellow]"
			)
			return 0

		module_name = str(getattr(args, "selected_module", "") or "").strip()
		if not module_name:
			self.console.print("[bold yellow]Module required. Available modules:[/bold yellow]")
			for name, discovered in plugins.items():
				self.console.print(f"  - {name}: {discovered.description}")
			return 2

		plugin = plugins.get(module_name)
		if plugin is None:
			self.console.print(f"[bold red]Unknown module:[/bold red] {module_name}")
			available = ", ".join(sorted(plugins.keys())[:25])
			self.console.print(f"[cyan]Available:[/cyan] {available}")
			return 2

		plugin_parser = argparse.ArgumentParser(prog=f"{args.command} {module_name}", add_help=False)
		plugin_parser.add_argument("-h", "--help", action="store_true", dest="_help")
		plugin.add_arguments(plugin_parser)

		module_args = list(getattr(args, "module_args", []) or [])
		if module_args and module_args[0] == "--":
			module_args = module_args[1:]

		if any(token in {"-h", "--help"} for token in module_args):
			plugin_parser.print_help()
			return 0

		try:
			parsed = plugin_parser.parse_args(module_args)
		except SystemExit:
			plugin_parser.print_help()
			return 2

		if getattr(parsed, "_help", False):
			plugin_parser.print_help()
			return 0

		return run_with_guard(
			lambda: plugin.run(parsed, self.context),
			console=self.console,
			logger_name=f"plugin:{plugin.name}",
			logger=self.logger,
		)

	def _build_parser(self) -> argparse.ArgumentParser:
		"""Construct the root parser and dynamic subcommand tree."""

		parser = argparse.ArgumentParser(
			prog="syctf",
			description="SYCTF - Terminal-only CTF Automation Toolkit",
		)
		parser.add_argument(
			"--no-banner",
			action="store_true",
			help="Disable animated startup banner.",
		)

		commands = parser.add_subparsers(dest="command")

		for command_name, category in COMMAND_CATEGORY_MAP.items():
			command_parser = commands.add_parser(command_name, help=f"Run {category} modules")
			command_parser.set_defaults(_category=category)
			command_parser.add_argument("selected_module", nargs="?", help="Module name in selected category")
			command_parser.add_argument("module_args", nargs=argparse.REMAINDER, help="Module arguments")

		plugin_parser = commands.add_parser("plugin", help="Manage external marketplace plugins")
		plugin_subparsers = plugin_parser.add_subparsers(dest="plugin_action", required=True)

		plugin_install = plugin_subparsers.add_parser("install", help="Install plugin pack")
		plugin_install.add_argument("plugin_name", help="Plugin name, e.g. web-ssti-pack")

		plugin_subparsers.add_parser("list", help="List installed plugins")

		plugin_remove = plugin_subparsers.add_parser("remove", help="Remove installed plugin")
		plugin_remove.add_argument("plugin_name", help="Installed plugin name")

		plugin_info = plugin_subparsers.add_parser("info", help="Show installed plugin details")
		plugin_info.add_argument("plugin_name", help="Installed plugin name")

		bench_parser = commands.add_parser("bench", help="Benchmark startup and module execution")
		bench_parser.add_argument("--category", default="misc", help="Plugin category for module benchmark")
		bench_parser.add_argument("--module", default="env-check", help="Module name for benchmark")
		bench_parser.add_argument("module_args", nargs=argparse.REMAINDER, help="Optional benchmark module args")

		commands.add_parser("ai-setup", help="Setup local AI environment for SYCTF")
		ai_parser = commands.add_parser("ai", help="AI-powered helper commands")
		ai_subparsers = ai_parser.add_subparsers(dest="ai_action")
		ai_exploit = ai_subparsers.add_parser("exploit", help="Generate exploit skeleton")
		ai_exploit.add_argument("binary_path", help="Path to ELF binary")
		ai_exploit.add_argument("--remote", help="Remote target host:port")
		ai_writeup = ai_subparsers.add_parser("writeup", help="Generate markdown writeup from session context")
		ai_writeup.add_argument("--model", default="deepseek-coder:6.7b", help="Ollama model name")

		commands.add_parser("shell", help="Start interactive SYCTF shell")
		return parser


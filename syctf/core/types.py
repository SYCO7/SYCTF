"""Core type definitions used across the SYCTF application."""

from __future__ import annotations

from dataclasses import dataclass, field
from logging import Logger
from pathlib import Path
from typing import Any, Protocol

from rich.console import Console


@dataclass(slots=True)
class AppConfig:
    """Runtime configuration loaded from .syctfconfig."""

    owner: str = "Tanmoy Mondal"
    github: str = "https://github.com/<USERNAME>"
    linkedin: str = "https://linkedin.com/in/<USERNAME>"
    portfolio: str = "https://<YOURWEBSITE>"
    request_timeout: float = 8.0
    connect_timeout: float = 1.5
    max_threads: int = 200
    user_agent: str = "SYCTF/1.0"
    default_wordlist: Path = Path("examples") / "wordlist.txt"
    ai_module_enabled: bool = False
    ai_auto_run: bool = True
    remote_pack_enabled: bool = False
    writeup_generator_enabled: bool = False


class ModulePlugin(Protocol):
    """Protocol every plugin module must implement."""

    name: str
    description: str

    def add_arguments(self, parser: Any) -> None:
        """Register module-specific CLI arguments."""

    def run(self, args: Any, context: "ExecutionContext") -> int:
        """Execute plugin logic and return an exit code."""


@dataclass(slots=True)
class ExecutionContext:
    """Shared state passed into module plugins."""

    config: AppConfig
    logger: Logger
    console: Console
    plugin_loader: Any
    cache: dict[str, Any] = field(default_factory=dict)

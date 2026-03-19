"""Secure execution helpers for commands and external tools."""

from __future__ import annotations

import subprocess
from logging import Logger
from pathlib import Path
from typing import Callable, TypeVar

from rich.console import Console

F = TypeVar("F", bound=Callable[..., int])


def safe_subprocess(
    argv: list[str],
    *,
    timeout: float = 20.0,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run subprocess safely without shell interpolation."""

    if not argv:
        raise ValueError("subprocess argv cannot be empty")
    if any("\x00" in arg for arg in argv):
        raise ValueError("null byte detected in subprocess argument")

    return subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        timeout=timeout,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )


def run_with_guard(
    func: Callable[[], int],
    *,
    console: Console,
    logger_name: str,
    logger: Logger,
) -> int:
    """Execute callable with robust exception handling and user-friendly errors."""

    try:
        return func()
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted by user.[/yellow]")
        logger.warning("%s interrupted by user", logger_name)
        return 130
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Error:[/bold red] {exc}")
        logger.exception("Unhandled exception in %s: %s", logger_name, exc)
        return 1

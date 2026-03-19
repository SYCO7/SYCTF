"""Pwntools availability helpers for optional pwn support."""

from __future__ import annotations

import platform
from typing import Any

try:
	from pwn import *  # noqa: F401,F403

	PWNLIB_AVAILABLE = True
except ImportError:
	PWNLIB_AVAILABLE = False

MISSING_PWNTOOLS_MESSAGE = (
	"[!] Pwntools not installed. Run on Linux or install with: pip install syctf[pwn]"
)
WINDOWS_PWN_LIMITED_MESSAGE = "Running in Windows mode. Pwn features limited."


def is_windows() -> bool:
	"""Return whether runtime platform is Windows."""

	return platform.system().lower() == "windows"


def print_windows_notice(console: Any) -> None:
	"""Print pwn feature limitation message on Windows."""

	if is_windows():
		console.print(WINDOWS_PWN_LIMITED_MESSAGE, markup=False)


def print_missing_pwntools(console: Any) -> None:
	"""Print missing pwntools guidance message."""

	console.print(MISSING_PWNTOOLS_MESSAGE, markup=False)

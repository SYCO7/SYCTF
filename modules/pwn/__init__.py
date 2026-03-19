"""Pwn helper plugins for SYCTF."""

try:
	from pwn import *  # noqa: F401,F403

	PWNLIB_AVAILABLE = True
except ImportError:
	PWNLIB_AVAILABLE = False

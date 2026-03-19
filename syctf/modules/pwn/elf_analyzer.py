"""Compatibility shim for legacy elf_analyzer import path."""

try:
    from pwn import *  # noqa: F401,F403

    PWNLIB_AVAILABLE = True
except ImportError:
    PWNLIB_AVAILABLE = False

from syctf.modules.pwn.elf_analyze import (  # noqa: F401
    ElfAnalyzePlugin,
    analyze_elf,
    description,
    name,
    plugin,
    run,
)

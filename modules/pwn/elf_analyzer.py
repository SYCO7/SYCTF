"""Compatibility shim for legacy elf_analyzer import path."""

from modules.pwn.elf_analyze import (  # noqa: F401
    ElfAnalyzePlugin,
    analyze_elf,
    description,
    name,
    plugin,
    run,
)

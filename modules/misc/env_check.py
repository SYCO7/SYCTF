"""Environment verification module."""

from __future__ import annotations

import argparse
import shutil

from syctf.core.types import ExecutionContext


class EnvCheckPlugin:
    """Check whether common CTF binaries are present on the host."""

    name = "env-check"
    description = "Check availability of common external CTF tools"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register plugin arguments."""

        parser.add_argument(
            "--tools",
            nargs="*",
            default=["python", "nmap", "gdb", "strings", "objdump"],
            help="Tool names to verify in PATH",
        )

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Print availability status for requested binaries."""

        for tool in args.tools:
            location = shutil.which(tool)
            if location:
                context.console.print(f"[green][OK][/green] {tool}: {location}")
            else:
                context.console.print(f"[yellow][MISSING][/yellow] {tool}")
        return 0


plugin = EnvCheckPlugin()

"""Hash identifier helper module."""

from __future__ import annotations

import argparse
import re

from syctf.core.types import ExecutionContext


class HashIdentifierPlugin:
    """Identify likely hash families using lightweight signatures."""

    name = "hash-ident"
    description = "Identify common hash algorithms from hash length/pattern"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register plugin arguments."""

        parser.add_argument("--hash", required=True, help="Hash string")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Identify possible algorithms for a provided hash string."""

        value = args.hash.strip().lower()
        if not re.fullmatch(r"[a-f0-9]+", value):
            context.console.print("[yellow]Input is not plain hex; result may be uncertain.[/yellow]")

        candidates: dict[int, list[str]] = {
            32: ["MD5", "NTLM"],
            40: ["SHA1"],
            56: ["SHA224"],
            64: ["SHA256", "BLAKE2s"],
            96: ["SHA384"],
            128: ["SHA512", "BLAKE2b"],
        }

        guesses = candidates.get(len(value), [])
        if not guesses:
            context.console.print("[red]No common signature match found.[/red]")
            return 1

        context.console.print("[bold green]Likely algorithms:[/bold green]")
        for algo in guesses:
            context.console.print(f"  - {algo}")
        return 0


plugin = HashIdentifierPlugin()

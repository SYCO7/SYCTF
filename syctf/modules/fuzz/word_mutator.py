"""Word mutation helper for fuzzing payload generation."""

from __future__ import annotations

import argparse

from syctf.core.types import ExecutionContext


class WordMutatorPlugin:
    """Generate quick payload mutations from an input token."""

    name = "word-mutator"
    description = "Generate basic fuzz mutations for a base word"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register plugin arguments."""

        parser.add_argument("--word", required=True, help="Base word to mutate")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Print generated mutations."""

        word = args.word.strip()
        if not word:
            raise ValueError("word cannot be empty")

        variants = {
            word,
            word.upper(),
            word.lower(),
            f"{word}123",
            f"../{word}",
            f"{word}%00",
            f"{word}.bak",
            f"{word}.php",
            f"{word}.txt",
        }
        for variant in sorted(variants):
            context.console.print(variant)
        return 0


plugin = WordMutatorPlugin()

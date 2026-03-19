"""Caesar cipher brute-force helper."""

from __future__ import annotations

import argparse

from syctf.core.types import ExecutionContext


def _shift_char(ch: str, shift: int) -> str:
    """Shift one alphabetical character by given amount."""

    if "a" <= ch <= "z":
        return chr((ord(ch) - ord("a") - shift) % 26 + ord("a"))
    if "A" <= ch <= "Z":
        return chr((ord(ch) - ord("A") - shift) % 26 + ord("A"))
    return ch


class CaesarBruteforcePlugin:
    """Brute-force all Caesar shifts for quick plaintext discovery."""

    name = "caesar-brute"
    description = "Bruteforce Caesar cipher shifts (0-25)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register plugin arguments."""

        parser.add_argument("--text", required=True, help="Ciphertext input")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Print all shift candidates."""

        for shift in range(26):
            candidate = "".join(_shift_char(ch, shift) for ch in args.text)
            context.console.print(f"[{shift:02d}] {candidate}")
        return 0


plugin = CaesarBruteforcePlugin()

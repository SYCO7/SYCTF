"""Decrypt an RSA ciphertext file with a recovered PEM private key.

Pairs with `forensics metadata` (which recovers keys hidden in images) to solve
StegoRSA-style challenges entirely from the menu. Uses the system openssl and
tries PKCS#1 then OAEP padding.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

from syctf.core.types import ExecutionContext
from syctf.flags.detector import FlagDetector


class RsaDecryptPlugin:
    """openssl-backed RSA decrypt of a ciphertext file with a PEM key."""

    name = "rsa-decrypt"
    description = "Decrypt an RSA ciphertext file with a PEM private key (tries PKCS#1/OAEP)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--key", required=True, help="Path to PEM private key")
        parser.add_argument("--file", required=True, help="Path to the encrypted ciphertext file")
        parser.add_argument("--padding", choices=["auto", "pkcs1", "oaep"], default="auto", help="RSA padding")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        openssl = shutil.which("openssl")
        if openssl is None:
            context.console.print("[bold red]openssl not found (install it: apt install openssl).[/bold red]")
            return 1
        key = Path(args.key).expanduser()
        enc = Path(args.file).expanduser()
        if not key.is_file() or not enc.is_file():
            context.console.print("[bold red]Key or ciphertext file not found.[/bold red]")
            return 2

        paddings = ["pkcs1", "oaep"] if args.padding == "auto" else [args.padding]
        detector = FlagDetector(custom_format=context.cache.get("flag_format"))
        context.logger.info("crypto rsa-decrypt key=%s file=%s", key, enc)

        for pad in paddings:
            try:
                out = subprocess.run(
                    [openssl, "pkeyutl", "-decrypt", "-inkey", str(key), "-in", str(enc),
                     "-pkeyopt", f"rsa_padding_mode:{pad}"],
                    capture_output=True, timeout=20,
                )
            except (subprocess.SubprocessError, OSError) as exc:
                context.console.print(f"[yellow]openssl error ({pad}): {exc}[/yellow]")
                continue
            if out.returncode != 0:
                continue
            text = out.stdout.decode("latin-1", "ignore")
            context.console.print(f"[bold green]Decrypted ({pad} padding):[/bold green]")
            context.console.print(text.strip()[:2000])
            for hit in detector.scan(text):
                if hit.real:
                    context.console.print(f"[bold green]FLAG:[/bold green] {hit.value}")
                    context.cache["flag"] = hit.value
                    return 0
            return 0

        context.console.print("[yellow]Decryption failed with all paddings — wrong key or format?[/yellow]")
        return 1


plugin = RsaDecryptPlugin()

"""Brute-force a ZipCrypto-protected ZIP password from a wordlist."""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

from syctf.core.types import ExecutionContext
from syctf.flags.detector import FlagDetector

_DEFAULTS = [
    "password", "123456", "admin", "letmein", "secret", "qwerty", "root",
    "flag", "ctf", "changeme", "infected", "password1", "12345678",
]


class ZipCrackPlugin:
    """Try passwords against an encrypted ZIP and scan the contents."""

    name = "zip-crack"
    description = "Brute-force a ZipCrypto password from a wordlist, then scan for the flag"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--file", required=True, help="Path to encrypted .zip")
        parser.add_argument("--wordlist", help="Password wordlist (defaults to a small built-in list)")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        path = Path(args.file).expanduser()
        if not path.is_file() or not zipfile.is_zipfile(path):
            context.console.print("[bold red]Not a valid ZIP file.[/bold red]")
            return 2

        words = _DEFAULTS
        if args.wordlist:
            wl = Path(args.wordlist).expanduser()
            if wl.is_file():
                words = wl.read_text(errors="ignore").splitlines()

        context.logger.info("forensics zip-crack file=%s words=%d", path, len(words))
        detector = FlagDetector(custom_format=context.cache.get("flag_format"))
        try:
            zf = zipfile.ZipFile(path)
            target = next((n for n in zf.namelist() if not n.endswith("/")), None)
        except zipfile.BadZipFile as exc:
            context.console.print(f"[bold red]ZIP error:[/bold red] {exc}")
            return 1
        if target is None:
            context.console.print("[yellow]ZIP has no files.[/yellow]")
            return 0

        for word in words:
            pw = word.strip()
            if not pw:
                continue
            try:
                data = zf.read(target, pwd=pw.encode())
            except (RuntimeError, zipfile.BadZipFile, NotImplementedError):
                continue
            except Exception:  # noqa: BLE001 - wrong password variants
                continue
            context.console.print(f"[bold green]Password found:[/bold green] {pw!r}")
            context.cache["zip_password"] = pw
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                try:
                    blob = zf.read(name, pwd=pw.encode())
                except Exception:  # noqa: BLE001
                    continue
                for hit in detector.scan(blob.decode("latin-1", "ignore")):
                    if hit.real:
                        context.console.print(f"[bold green]FLAG in {name}:[/bold green] {hit.value}")
                        context.cache["flag"] = hit.value
                        return 0
            context.console.print("[dim]Extracted, but no flag matched inside.[/dim]")
            return 0

        context.console.print("[yellow]Password not in wordlist. (Note: AES-encrypted ZIPs need pyzipper.)[/yellow]")
        return 1


plugin = ZipCrackPlugin()

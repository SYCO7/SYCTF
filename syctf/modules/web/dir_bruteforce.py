"""Simple directory bruteforce module for web CTFs."""

from __future__ import annotations

import argparse
from urllib.parse import urljoin

import requests

from syctf.core.types import ExecutionContext
from syctf.core.validation import validate_existing_file, validate_url


DEFAULT_WORDS = [
    "admin",
    "login",
    "uploads",
    "backup",
    "api",
    "dashboard",
    "robots.txt",
]


class DirBruteforcePlugin:
    """Bruteforce directories from a wordlist."""

    name = "dir-bruteforce"
    description = "Directory bruteforce against a target URL"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register plugin arguments."""

        parser.add_argument("--url", required=True, help="Target base URL")
        parser.add_argument("--wordlist", help="Wordlist path (one entry per line)")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Execute directory bruteforce routine."""

        base_url = validate_url(args.url)
        base_url = base_url if base_url.endswith("/") else f"{base_url}/"

        words = DEFAULT_WORDS
        if args.wordlist:
            path = validate_existing_file(args.wordlist)
            words = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if not words:
                raise ValueError("Provided wordlist is empty")

        session = requests.Session()
        headers = {"User-Agent": context.config.user_agent}
        hits: list[tuple[int, str]] = []
        good_codes = {200, 204, 301, 302, 307, 401, 403}

        for entry in words:
            target = urljoin(base_url, entry)
            try:
                response = session.get(target, timeout=context.config.request_timeout, headers=headers)
            except requests.RequestException:
                continue
            if response.status_code in good_codes:
                hits.append((response.status_code, target))

        if not hits:
            context.console.print("[yellow]No interesting directories found.[/yellow]")
            return 0

        context.console.print("[bold green]Potential findings:[/bold green]")
        for status, location in hits:
            context.console.print(f"[{status}] {location}")
        return 0


plugin = DirBruteforcePlugin()

"""robots.txt reconnaissance module."""

from __future__ import annotations

import argparse
from urllib.parse import urljoin

import requests

from syctf.core.types import ExecutionContext
from syctf.core.validation import validate_url


class RobotsFetchPlugin:
    """Download and print robots.txt content from a target host."""

    name = "robots"
    description = "Fetch robots.txt from a target URL"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register plugin arguments."""

        parser.add_argument("--url", required=True, help="Base URL (e.g. https://site)")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Execute robots.txt retrieval."""

        base = validate_url(args.url)
        target = urljoin(base if base.endswith("/") else f"{base}/", "robots.txt")
        context.logger.info("Recon robots target=%s", target)

        response = requests.get(
            target,
            timeout=context.config.request_timeout,
            headers={"User-Agent": context.config.user_agent},
        )
        context.console.print(f"[bold cyan]Status:[/bold cyan] {response.status_code}")
        context.console.print(response.text if response.text else "[yellow]Empty robots.txt[/yellow]")
        return 0


plugin = RobotsFetchPlugin()

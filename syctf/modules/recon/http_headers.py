"""HTTP header reconnaissance module."""

from __future__ import annotations

import argparse

import requests
from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.core.validation import validate_url


class HttpHeadersPlugin:
    """Fetch and print HTTP response headers."""

    name = "http-headers"
    description = "Fetch HTTP response headers from a target URL"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register plugin arguments."""

        parser.add_argument("--url", required=True, help="Target URL")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Execute the headers fetch workflow."""

        url = validate_url(args.url)
        context.logger.info("Recon http-headers target=%s", url)

        response = requests.get(
            url,
            timeout=context.config.request_timeout,
            headers={"User-Agent": context.config.user_agent},
            allow_redirects=True,
        )

        table = Table(title=f"HTTP Headers: {url}")
        table.add_column("Header", style="cyan", no_wrap=True)
        table.add_column("Value", style="green")
        for key, value in response.headers.items():
            table.add_row(key, value)
        context.console.print(table)
        return 0


plugin = HttpHeadersPlugin()

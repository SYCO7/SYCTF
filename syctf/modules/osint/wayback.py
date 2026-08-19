"""Historical URL discovery via the Wayback Machine CDX API."""

from __future__ import annotations

import argparse

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.utils.net_utils import http_json, valid_domain


class WaybackPlugin:
    """List archived URLs for a domain (great for finding old endpoints)."""

    name = "wayback"
    description = "Historical URL discovery via the Wayback Machine (archive.org CDX)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--domain", required=True, help="Domain to search (matches subpaths)")
        parser.add_argument("--limit", type=int, default=100, help="Max URLs to display")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        try:
            domain = valid_domain(args.domain)
        except ValueError as exc:
            context.console.print(f"[bold red]{exc}[/bold red]")
            return 2

        limit = max(1, int(args.limit))
        timeout = max(12.0, float(getattr(context.config, "request_timeout", 12.0)))
        context.logger.info("OSINT wayback domain=%s limit=%d", domain, limit)
        rows = http_json(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{domain}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": str(limit),
            },
            timeout=timeout,
        )

        # CDX returns [["original"], [url], [url], ...]; first row is the header.
        if not isinstance(rows, list) or len(rows) <= 1:
            context.console.print(f"[yellow]No archived URLs found for {domain}.[/yellow]")
            return 0

        urls = [str(r[0]) for r in rows[1:] if isinstance(r, list) and r]
        table = Table(title=f"Archived URLs for {domain} ({len(urls)})")
        table.add_column("#", style="cyan", no_wrap=True)
        table.add_column("URL", style="green")
        for idx, url in enumerate(urls, 1):
            table.add_row(str(idx), url)
        context.console.print(table)
        context.cache["osint_wayback"] = urls
        return 0


plugin = WaybackPlugin()

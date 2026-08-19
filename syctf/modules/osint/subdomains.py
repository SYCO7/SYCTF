"""Passive subdomain enumeration via crt.sh certificate transparency."""

from __future__ import annotations

import argparse

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.utils.net_utils import http_json, valid_domain


class SubdomainsPlugin:
    """Enumerate subdomains from public certificate transparency logs."""

    name = "subdomains"
    description = "Passive subdomain enumeration (crt.sh certificate transparency)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--domain", required=True, help="Registrable domain, e.g. example.com")
        parser.add_argument("--limit", type=int, default=200, help="Max subdomains to display")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        try:
            domain = valid_domain(args.domain)
        except ValueError as exc:
            context.console.print(f"[bold red]{exc}[/bold red]")
            return 2

        context.logger.info("OSINT subdomains domain=%s", domain)
        timeout = max(10.0, float(getattr(context.config, "request_timeout", 12.0)))
        data = http_json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=timeout)

        if not isinstance(data, list):
            context.console.print("[yellow]No data from crt.sh (rate-limited or empty). Try again later.[/yellow]")
            return 0

        found: set[str] = set()
        for row in data:
            name_value = str(row.get("name_value", "")) if isinstance(row, dict) else ""
            for name in name_value.splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain):
                    found.add(name)

        if not found:
            context.console.print(f"[yellow]No subdomains found for {domain}.[/yellow]")
            return 0

        ordered = sorted(found)[: max(1, int(args.limit))]
        table = Table(title=f"Subdomains of {domain} ({len(found)} unique)")
        table.add_column("#", style="cyan", no_wrap=True)
        table.add_column("Subdomain", style="green")
        for idx, name in enumerate(ordered, 1):
            table.add_row(str(idx), name)
        context.console.print(table)
        context.cache["osint_subdomains"] = ordered
        return 0


plugin = SubdomainsPlugin()

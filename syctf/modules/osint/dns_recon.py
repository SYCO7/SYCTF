"""DNS reconnaissance over DNS-over-HTTPS (no external resolver binary)."""

from __future__ import annotations

import argparse

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.utils.net_utils import http_json, valid_domain

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")


class DnsReconPlugin:
    """Resolve common DNS record types via Google Public DNS (DoH)."""

    name = "dns-recon"
    description = "DNS record enumeration over DNS-over-HTTPS (A/AAAA/MX/NS/TXT/CNAME/SOA)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--domain", required=True, help="Domain to resolve")
        parser.add_argument("--types", default=",".join(_RECORD_TYPES), help="Comma-separated record types")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        try:
            domain = valid_domain(args.domain)
        except ValueError as exc:
            context.console.print(f"[bold red]{exc}[/bold red]")
            return 2

        rtypes = [t.strip().upper() for t in str(args.types).split(",") if t.strip()]
        timeout = max(8.0, float(getattr(context.config, "request_timeout", 12.0)))
        context.logger.info("OSINT dns-recon domain=%s types=%s", domain, rtypes)

        table = Table(title=f"DNS records for {domain}")
        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("Answer", style="green")
        any_found = False

        for rtype in rtypes:
            data = http_json(
                "https://dns.google/resolve",
                params={"name": domain, "type": rtype},
                timeout=timeout,
            )
            answers = data.get("Answer", []) if isinstance(data, dict) else []
            values = [str(a.get("data", "")).strip() for a in answers if isinstance(a, dict)]
            values = [v for v in values if v]
            if values:
                any_found = True
                table.add_row(rtype, "\n".join(values))

        if not any_found:
            context.console.print(f"[yellow]No DNS records resolved for {domain}.[/yellow]")
            return 0

        context.console.print(table)
        return 0


plugin = DnsReconPlugin()

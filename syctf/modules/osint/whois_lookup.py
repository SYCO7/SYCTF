"""Domain registration lookup via RDAP (structured JSON WHOIS successor)."""

from __future__ import annotations

import argparse

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.utils.net_utils import http_json, valid_domain


def _events(data: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for event in data.get("events", []) or []:
        if isinstance(event, dict) and event.get("eventAction"):
            out[str(event["eventAction"])] = str(event.get("eventDate", ""))
    return out


class WhoisPlugin:
    """Look up domain registration data through the RDAP bootstrap."""

    name = "whois"
    description = "Domain registration lookup via RDAP (registrar, dates, nameservers, status)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--domain", required=True, help="Domain to look up")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        try:
            domain = valid_domain(args.domain)
        except ValueError as exc:
            context.console.print(f"[bold red]{exc}[/bold red]")
            return 2

        timeout = max(8.0, float(getattr(context.config, "request_timeout", 12.0)))
        context.logger.info("OSINT whois(rdap) domain=%s", domain)
        data = http_json(f"https://rdap.org/domain/{domain}", timeout=timeout)

        if not isinstance(data, dict) or "errorCode" in data:
            context.console.print(f"[yellow]No RDAP record for {domain}.[/yellow]")
            return 0

        events = _events(data)
        nameservers = [str(ns.get("ldhName", "")) for ns in data.get("nameservers", []) or [] if isinstance(ns, dict)]
        statuses = [str(s) for s in data.get("status", []) or []]

        registrar = ""
        for entity in data.get("entities", []) or []:
            if isinstance(entity, dict) and "registrar" in (entity.get("roles") or []):
                for item in entity.get("vcardArray", [[], []])[1] or []:
                    if isinstance(item, list) and item and item[0] == "fn":
                        registrar = str(item[-1])

        table = Table(title=f"RDAP: {domain}", show_header=False)
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_row("handle", str(data.get("handle", "")))
        table.add_row("registrar", registrar or "(unknown)")
        table.add_row("registered", events.get("registration", ""))
        table.add_row("expires", events.get("expiration", ""))
        table.add_row("last changed", events.get("last changed", ""))
        table.add_row("status", ", ".join(statuses) or "(none)")
        table.add_row("nameservers", "\n".join(n for n in nameservers if n) or "(none)")
        context.console.print(table)
        return 0


plugin = WhoisPlugin()

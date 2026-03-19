"""Quick web parameter fuzz helper for SSTI/LFI signal checks."""

from __future__ import annotations

import argparse
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from syctf.core.types import ExecutionContext
from syctf.core.validation import validate_url

name = "quick-fuzz"
description = "Quick parameter discovery with SSTI and LFI payload checks"

DEFAULT_PARAMS = ["id", "file", "page", "template", "name", "q", "view"]
SSTI_PAYLOADS = ["{{7*7}}", "${7*7}"]
LFI_PAYLOADS = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]


class QuickFuzzPlugin:
    """Run fast, practical web parameter fuzz checks for CTF triage."""

    name = name
    description = description

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register quick fuzz arguments."""

        parser.add_argument("url", help="Target base URL")
        parser.add_argument("--timeout", type=float, default=6.0, help="HTTP timeout seconds")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Execute fast discovery + SSTI/LFI probe flow."""

        base = validate_url(args.url)
        parsed = urlparse(base)
        seed_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        params = list(dict.fromkeys([*seed_params.keys(), *DEFAULT_PARAMS]))

        session = requests.Session()
        findings: list[str] = []

        for param in params:
            for payload in [*SSTI_PAYLOADS, *LFI_PAYLOADS]:
                query = dict(seed_params)
                query[param] = payload
                target = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

                try:
                    resp = session.get(
                        target,
                        timeout=max(1.0, float(args.timeout)),
                        headers={"User-Agent": context.config.user_agent},
                        allow_redirects=True,
                    )
                except requests.RequestException:
                    continue

                body = resp.text.lower()
                ssti_signal = payload in SSTI_PAYLOADS and ("49" in body or payload.lower() in body)
                lfi_signal = payload in LFI_PAYLOADS and (
                    "root:x:0:0" in body or "[extensions]" in body or "for 16-bit app support" in body
                )
                server_error = resp.status_code >= 500

                if ssti_signal or lfi_signal or server_error:
                    tags: list[str] = []
                    if ssti_signal:
                        tags.append("ssti-signal")
                    if lfi_signal:
                        tags.append("lfi-signal")
                    if server_error:
                        tags.append("5xx")
                    findings.append(f"[{resp.status_code}] {param}={payload} -> {target} ({', '.join(tags)})")

        if not findings:
            context.console.print("[yellow]quick-fuzz: no strong SSTI/LFI signals found.[/yellow]")
            return 0

        context.console.print("[bold green]quick-fuzz findings:[/bold green]")
        for line in findings[:40]:
            context.console.print(line)
        return 0


plugin = QuickFuzzPlugin()

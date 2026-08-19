"""Check S3 bucket existence and public exposure (unauthenticated)."""

from __future__ import annotations

import argparse
import re

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.utils.net_utils import http_get

_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")
_SUFFIXES = ("", "-dev", "-prod", "-staging", "-backup", "-assets", "-static", "-uploads", "-data", "-public")


class S3EnumPlugin:
    """Probe S3 bucket names for existence and public-listing exposure."""

    name = "s3-enum"
    description = "Check S3 bucket existence + public read/listing (with name permutations)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--bucket", required=True, help="Base bucket name (permutations auto-added)")
        parser.add_argument("--no-permutations", action="store_true", help="Check only the exact name")

    def _classify(self, status: int, body: str) -> str:
        if status == 200 and "<ListBucketResult" in body:
            return "PUBLIC (listable)"
        if status == 200:
            return "exists (200)"
        if status == 403:
            return "exists (private)"
        if status == 404 or "NoSuchBucket" in body:
            return "no bucket"
        return f"http {status}"

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        base = str(args.bucket).strip().lower()
        if not _BUCKET_RE.match(base):
            context.console.print("[bold red]Invalid S3 bucket name.[/bold red]")
            return 2

        candidates = [base] if args.no_permutations else sorted({base + s for s in _SUFFIXES})
        timeout = max(6.0, float(getattr(context.config, "request_timeout", 8.0)))
        context.logger.info("cloud s3-enum base=%s n=%d", base, len(candidates))

        table = Table(title=f"S3 enumeration: {base}")
        table.add_column("Bucket", style="cyan")
        table.add_column("Result", style="white")
        table.add_column("URL", style="dim")
        hits = 0
        for name in candidates:
            url = f"https://{name}.s3.amazonaws.com/"
            response = http_get(url, timeout=timeout)
            if response is None:
                table.add_row(name, "error", url)
                continue
            verdict = self._classify(response.status_code, response.text or "")
            if "no bucket" not in verdict:
                hits += 1
            color = "green" if "PUBLIC" in verdict else ("yellow" if "exists" in verdict else "dim")
            table.add_row(name, f"[{color}]{verdict}[/{color}]", url)

        context.console.print(table)
        context.console.print(f"[dim]{hits} bucket(s) appear to exist.[/dim]")
        return 0


plugin = S3EnumPlugin()

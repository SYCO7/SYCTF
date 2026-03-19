"""Parameter fuzzing helper for web challenge workflows."""

from __future__ import annotations

import argparse
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from syctf.core.types import ExecutionContext
from syctf.core.validation import validate_url

name = "param-fuzzer"
description = "Basic query parameter fuzzing for reflected behavior"

DEFAULT_PARAM_NAMES = ["id", "q", "search", "file", "page", "user"]


class ParamFuzzerPlugin:
    """Fuzz query parameters with a payload and report response deltas."""

    name = name
    description = description

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register plugin arguments."""

        parser.add_argument("--url", help="Target URL")
        parser.add_argument(
            "--params",
            help="Comma-separated param list. Default: id,q,search,file,page,user",
        )
        parser.add_argument(
            "--payload",
            default="' OR '1'='1",
            help="Injection payload",
        )
        parser.add_argument(
            "text",
            nargs="?",
            default="",
            help="Optional challenge text used to auto-extract URL",
        )

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Execute parameter fuzzing against URL query args."""

        url = args.url or _extract_url_from_text(args.text or "")
        if not url:
            raise ValueError("No URL supplied. Use --url or provide text containing http(s) URL.")

        target = validate_url(url)
        parsed = urlparse(target)

        payload = str(args.payload)
        names = _parse_param_names(args.params)

        existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if existing:
            names = list(dict.fromkeys([*existing.keys(), *names]))

        if not names:
            names = list(DEFAULT_PARAM_NAMES)

        context.console.print("[bold cyan]Parameter Fuzz Results[/bold cyan]")
        session = requests.Session()
        found = 0

        for param_name in names:
            query_map = dict(existing)
            query_map[param_name] = payload
            fuzzed_url = urlunparse(parsed._replace(query=urlencode(query_map, doseq=True)))

            try:
                response = session.get(
                    fuzzed_url,
                    timeout=context.config.request_timeout,
                    headers={"User-Agent": context.config.user_agent},
                    allow_redirects=True,
                )
            except requests.RequestException:
                continue

            body = response.text.lower()
            reflected = payload.lower() in body
            possible_error = any(marker in body for marker in ["sql", "syntax", "warning", "exception"])

            if reflected or possible_error or response.status_code >= 500:
                found += 1
                notes = []
                if reflected:
                    notes.append("payload-reflected")
                if possible_error:
                    notes.append("error-signature")
                if response.status_code >= 500:
                    notes.append("5xx")
                context.console.print(
                    f"[{response.status_code}] {param_name} -> {fuzzed_url} ({', '.join(notes)})"
                )

        if found == 0:
            context.console.print("[yellow]No strong parameter-fuzzing signals detected.[/yellow]")
        return 0


plugin = ParamFuzzerPlugin()


def _extract_url_from_text(text: str) -> str | None:
    """Extract first URL from arbitrary input text."""

    match = re.search(r"https?://[^\s'\"]+", text, re.IGNORECASE)
    return match.group(0) if match else None


def _parse_param_names(params_raw: str | None) -> list[str]:
    """Normalize comma-separated parameter names."""

    if not params_raw:
        return list(DEFAULT_PARAM_NAMES)
    out: list[str] = []
    for item in params_raw.split(","):
        key = item.strip().lstrip("?").strip()
        if key:
            out.append(key)
    return out

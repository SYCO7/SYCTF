"""Quick web reconnaissance engine for safe CTF triage."""

from __future__ import annotations

import asyncio
import argparse
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx
from rich.panel import Panel
from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.core.validation import validate_url

name = "quick-recon"
description = "Fast low-noise web reconnaissance with reflection checks"

DEFAULT_DIR_WORDS = ["admin", "login", "api", "debug"]
DEFAULT_FALLBACK_PARAMS = ["id", "q", "search", "file", "page", "name"]
FUZZ_PAYLOADS: dict[str, str] = {
    "SSTI": "{{7*7}}",
    "LFI": "../../../../etc/passwd",
    "SQLi": "' OR 1=1--",
}
TRACE_MARKERS = [
    "traceback",
    "exception",
    "stack trace",
    "fatal error",
    "sql syntax",
    "warning:",
    "notice:",
]


class _FormParser(HTMLParser):
    """Lightweight HTML parser for form/input discovery without extra deps."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, str]] = []
        self.inputs: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs_map = {str(key).lower(): str(value) for key, value in attrs if key and value is not None}
        lowered = tag.lower()
        if lowered == "form":
            self.forms.append(
                {
                    "method": attrs_map.get("method", "get").upper(),
                    "action": attrs_map.get("action", ""),
                }
            )
        if lowered == "input":
            field_name = attrs_map.get("name", "").strip()
            if field_name:
                self.inputs.append(field_name)


class QuickReconPlugin:
    """Perform quick, bounded reconnaissance against a web target."""

    name = name
    description = description

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register quick-recon arguments."""

        parser.add_argument("url", help="Target URL")
        parser.add_argument("--timeout", type=float, default=6.0, help="Per-request timeout seconds")
        parser.add_argument(
            "--max-requests",
            type=int,
            default=18,
            help="Hard cap for total HTTP requests (safety guard)",
        )

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Run full reconnaissance flow with strict request budget."""

        url = validate_url(args.url)
        timeout = max(1.0, min(float(args.timeout), 20.0))
        max_requests = max(6, min(int(args.max_requests), 40))

        result = asyncio.run(
            _run_async(
                url=url,
                timeout=timeout,
                max_requests=max_requests,
                user_agent=context.config.user_agent,
            )
        )

        if result is None:
            context.console.print("[bold red]quick-recon failed:[/bold red] unable to fetch base URL")
            return 1

        _render(
            console=context.console,
            url=url,
            request_count=int(result["request_count"]),
            max_requests=max_requests,
            forms=list(result["forms"]),
            inputs=list(result["inputs"]),
            query_params=list(result["query_params"]),
            fuzz_results=list(result["fuzz_results"]),
            header_info=dict(result["header_info"]),
            dir_results=list(result["dir_results"]),
            classifier=dict(result["classifier"]),
        )

        context.cache["quick_recon_result"] = {
            "url": url,
            "requests": int(result["request_count"]),
            "forms": list(result["forms"]),
            "inputs": list(result["inputs"]),
            "query_params": list(result["query_params"]),
            "fuzz_findings": list(result["fuzz_results"]),
            "headers": dict(result["header_info"]),
            "dirs": list(result["dir_results"]),
            "classifier": dict(result["classifier"]),
        }
        return 0


async def _run_async(*, url: str, timeout: float, max_requests: int, user_agent: str) -> dict[str, Any] | None:
    """Execute full recon flow asynchronously using bounded httpx requests."""

    request_count = 0
    response_signals: list[str] = []

    async with httpx.AsyncClient(headers={"User-Agent": user_agent}, follow_redirects=False) as client:
        base_resp, request_count, base_loop = await _safe_get(
            client,
            url,
            timeout=timeout,
            request_count=request_count,
            max_requests=max_requests,
            allow_redirects=True,
        )
        if base_resp is None:
            return None

        if base_loop:
            response_signals.append("Potential redirect loop detected on base request")

        parser = _FormParser()
        parser.feed(base_resp.text)

        query_params = [key for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
        form_params = list(dict.fromkeys(parser.inputs))
        action_params = _extract_query_params_from_actions(url, parser.forms)
        discovered_params = list(dict.fromkeys([*query_params, *form_params, *action_params]))

        fuzz_params = discovered_params[:8] if discovered_params else list(DEFAULT_FALLBACK_PARAMS)
        fuzz_results: list[dict[str, Any]] = []

        for param in fuzz_params:
            for kind, payload in FUZZ_PAYLOADS.items():
                if request_count >= max_requests:
                    break

                fuzz_url = _build_fuzz_url(url, param, payload)
                resp, request_count, looped = await _safe_get(
                    client,
                    fuzz_url,
                    timeout=timeout,
                    request_count=request_count,
                    max_requests=max_requests,
                    allow_redirects=True,
                )
                if resp is None:
                    continue

                body_lower = resp.text.lower()
                reflected = payload.lower() in body_lower
                indicators: list[str] = []

                if kind == "SSTI" and ("49" in body_lower or reflected):
                    indicators.append("ssti-signal")
                if kind == "LFI" and (
                    "root:x:0:0" in body_lower
                    or "for 16-bit app support" in body_lower
                    or reflected
                ):
                    indicators.append("lfi-signal")
                if kind == "SQLi" and ("sql" in body_lower or "syntax" in body_lower or reflected):
                    indicators.append("sqli-signal")
                if reflected:
                    indicators.append("reflected")
                if looped:
                    indicators.append("redirect-loop")

                if indicators:
                    fuzz_results.append(
                        {
                            "param": param,
                            "payload": payload,
                            "type": kind,
                            "status": resp.status_code,
                            "indicators": indicators,
                        }
                    )

        dir_results: list[tuple[str, int, str]] = []
        for word in DEFAULT_DIR_WORDS:
            if request_count >= max_requests:
                break
            target = urljoin(url if url.endswith("/") else f"{url}/", word)
            resp, request_count, looped = await _safe_get(
                client,
                target,
                timeout=timeout,
                request_count=request_count,
                max_requests=max_requests,
                allow_redirects=False,
            )
            if resp is None:
                continue
            if looped:
                response_signals.append(f"Redirect loop detected while probing /{word}")
            if resp.status_code in {200, 204, 301, 302, 307, 401, 403}:
                dir_results.append((word, resp.status_code, target))

    header_info = _header_summary(base_resp)
    classifier = _classify_response(base_resp, fuzz_results, response_signals)

    return {
        "request_count": request_count,
        "forms": parser.forms,
        "inputs": form_params,
        "query_params": list(dict.fromkeys([*query_params, *action_params])),
        "fuzz_results": fuzz_results,
        "header_info": header_info,
        "dir_results": dir_results,
        "classifier": classifier,
    }


async def _safe_get(
    session: httpx.AsyncClient,
    url: str,
    *,
    timeout: float,
    request_count: int,
    max_requests: int,
    allow_redirects: bool,
) -> tuple[httpx.Response | None, int, bool]:
    """Send bounded GET request and detect redirect-loop style behavior."""

    if request_count >= max_requests:
        return (None, request_count, False)

    try:
        response = await session.get(url, timeout=timeout, follow_redirects=allow_redirects)
        request_count += 1
    except httpx.TooManyRedirects:
        return (None, request_count + 1, True)
    except httpx.HTTPError:
        return (None, request_count + 1, False)

    # Heuristic: unusually long redirect history may indicate a loop.
    looped = len(response.history) >= 8
    return (response, request_count, looped)


def _extract_query_params_from_actions(base_url: str, forms: list[dict[str, str]]) -> list[str]:
    """Extract query keys from form action URLs."""

    out: list[str] = []
    for form in forms:
        action = str(form.get("action", "")).strip()
        if not action:
            continue
        action_url = urljoin(base_url, action)
        parsed = urlparse(action_url)
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
            if key:
                out.append(key)
    return out


def _build_fuzz_url(base_url: str, param: str, payload: str) -> str:
    """Build URL with one fuzzed query parameter."""

    parsed = urlparse(base_url)
    existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
    existing[param] = payload
    return urlunparse(parsed._replace(query=urlencode(existing, doseq=True)))


def _header_summary(response: httpx.Response) -> dict[str, str]:
    """Collect key reconnaissance headers."""

    server = response.headers.get("Server", "(missing)")
    powered = response.headers.get("X-Powered-By", "(missing)")
    csp = response.headers.get("Content-Security-Policy", "(missing)")

    cookies = response.headers.get("Set-Cookie", "")
    if cookies:
        cookie_names = sorted(set(re.findall(r"(?i)([A-Za-z0-9_\-]+)=", cookies)))
        cookie_text = ", ".join(cookie_names[:10]) if cookie_names else "present"
    else:
        cookie_text = "(none)"

    return {
        "server": server,
        "x-powered-by": powered,
        "cookies": cookie_text,
        "csp": csp,
    }


def _classify_response(
    base_response: httpx.Response,
    fuzz_results: list[dict[str, Any]],
    response_signals: list[str],
) -> dict[str, Any]:
    """Classify response quality and suspicious server behavior."""

    body = base_response.text.lower()
    status = base_response.status_code

    trace_hits = [marker for marker in TRACE_MARKERS if marker in body]
    if trace_hits:
        response_signals.append(f"Error trace indicators: {', '.join(trace_hits[:4])}")

    severity = "low"
    if status >= 500 or trace_hits:
        severity = "high"
    elif status >= 400 or fuzz_results:
        severity = "medium"

    return {
        "status_code": status,
        "redirects": len(base_response.history),
        "severity": severity,
        "signals": response_signals,
    }


def _render(
    *,
    console,
    url: str,
    request_count: int,
    max_requests: int,
    forms: list[dict[str, str]],
    inputs: list[str],
    query_params: list[str],
    fuzz_results: list[dict[str, Any]],
    header_info: dict[str, str],
    dir_results: list[tuple[str, int, str]],
    classifier: dict[str, Any],
) -> None:
    """Render quick-recon findings using rich tables and hints panel."""

    discovery = Table(title="Parameter Discovery")
    discovery.add_column("Signal", style="cyan", no_wrap=True)
    discovery.add_column("Count", style="green", no_wrap=True)
    discovery.add_column("Preview", style="white")
    discovery.add_row("Forms", str(len(forms)), ", ".join([f.get("action", "/") for f in forms[:3]]) or "none")
    discovery.add_row("Inputs", str(len(inputs)), ", ".join(inputs[:6]) or "none")
    discovery.add_row("Query Params", str(len(query_params)), ", ".join(query_params[:6]) or "none")

    fuzz_table = Table(title="Basic Fuzz Signals")
    fuzz_table.add_column("Type", style="magenta", no_wrap=True)
    fuzz_table.add_column("Param", style="cyan", no_wrap=True)
    fuzz_table.add_column("Status", style="green", no_wrap=True)
    fuzz_table.add_column("Indicators", style="white")
    if not fuzz_results:
        fuzz_table.add_row("-", "-", "-", "No reflected/high-signal responses")
    else:
        for item in fuzz_results[:25]:
            fuzz_table.add_row(
                str(item["type"]),
                str(item["param"]),
                str(item["status"]),
                ", ".join(item["indicators"]),
            )

    headers = Table(title="Header Analysis")
    headers.add_column("Header", style="cyan", no_wrap=True)
    headers.add_column("Value", style="white")
    headers.add_row("Server", header_info["server"])
    headers.add_row("X-Powered-By", header_info["x-powered-by"])
    headers.add_row("Cookies", header_info["cookies"])
    headers.add_row("CSP", header_info["csp"])

    dirs = Table(title="Directory Guess")
    dirs.add_column("Path", style="cyan", no_wrap=True)
    dirs.add_column("Status", style="green", no_wrap=True)
    dirs.add_column("URL", style="white")
    if not dir_results:
        dirs.add_row("-", "-", "No interesting directory hits")
    else:
        for word, status, location in dir_results:
            dirs.add_row(word, str(status), location)

    severity = str(classifier.get("severity", "low")).upper()
    signal_lines = list(classifier.get("signals", []))

    hints: list[str] = [
        f"Target: {url}",
        f"Requests used: {request_count}/{max_requests}",
        f"Base status: {classifier.get('status_code')} redirects={classifier.get('redirects')}",
        f"Classifier severity: {severity}",
    ]

    if fuzz_results:
        hints.append("Fuzz signals detected: inspect reflected parameters and backend error behavior")
    if dir_results:
        hints.append("Directory hits found: prioritize authenticated endpoints and debug routes")
    if header_info.get("csp", "(missing)") == "(missing)":
        hints.append("CSP missing: evaluate XSS attack surface")
    if header_info.get("x-powered-by", "(missing)") != "(missing)":
        hints.append("X-Powered-By exposed: fingerprint framework/version")

    for signal in signal_lines[:6]:
        hints.append(f"Signal: {signal}")

    console.print(Panel(discovery, title="Quick Recon", border_style="cyan"))
    console.print(fuzz_table)
    console.print(headers)
    console.print(dirs)
    console.print(Panel("\n".join(hints), title="Hint Suggestions", border_style="yellow"))


plugin = QuickReconPlugin()

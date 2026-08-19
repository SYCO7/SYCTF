"""Username presence checking across platforms (Sherlock-lite)."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.utils.net_utils import http_get

# Sites with reliable 200/404 semantics for a profile path.
_SITES: dict[str, str] = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Reddit": "https://www.reddit.com/user/{u}",
    "Keybase": "https://keybase.io/{u}",
    "HackerOne": "https://hackerone.com/{u}",
    "PyPI": "https://pypi.org/user/{u}/",
    "Replit": "https://replit.com/@{u}",
    "Medium": "https://medium.com/@{u}",
    "Dev.to": "https://dev.to/{u}",
    "GitBook": "https://{u}.gitbook.io/",
    "TryHackMe": "https://tryhackme.com/p/{u}",
}


class UsernameEnumPlugin:
    """Check whether a username exists on a set of platforms."""

    name = "username-enum"
    description = "Check username presence across platforms (GitHub, GitLab, Reddit, ...)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--username", required=True, help="Username / handle to check")
        parser.add_argument("--threads", type=int, default=10, help="Concurrent requests")

    def _check(self, site: str, template: str, username: str, timeout: float) -> tuple[str, str, str]:
        response = http_get(template.format(u=username), timeout=timeout, follow_redirects=False)
        if response is None:
            return site, "error", template.format(u=username)
        code = response.status_code
        if code in (301, 302) and "location" in response.headers:
            # Redirect to login/home usually means "not found".
            verdict = "unknown"
        elif code == 200:
            verdict = "FOUND"
        elif code in (404, 410):
            verdict = "free"
        else:
            verdict = f"http {code}"
        return site, verdict, template.format(u=username)

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        username = str(args.username).strip()
        if not username or "/" in username or " " in username:
            context.console.print("[bold red]Invalid username.[/bold red]")
            return 2

        timeout = max(6.0, float(getattr(context.config, "connect_timeout", 6.0)) + 5.0)
        threads = max(1, min(int(args.threads), 20))
        context.logger.info("OSINT username-enum user=%s", username)

        rows: list[tuple[str, str, str]] = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(self._check, s, t, username, timeout) for s, t in _SITES.items()]
            for future in as_completed(futures):
                rows.append(future.result())

        rank = {"FOUND": 0, "free": 1, "unknown": 2}
        rows.sort(key=lambda r: (rank.get(r[1], 3), r[0]))

        table = Table(title=f"Username '{username}' across {len(_SITES)} sites")
        table.add_column("Site", style="cyan", no_wrap=True)
        table.add_column("Result", style="white")
        table.add_column("URL", style="dim")
        for site, verdict, url in rows:
            color = {"FOUND": "green", "free": "yellow"}.get(verdict, "white")
            table.add_row(site, f"[{color}]{verdict}[/{color}]", url)
        context.console.print(table)
        context.console.print("[dim]Note: SPA sites can yield false positives; verify hits manually.[/dim]")
        return 0


plugin = UsernameEnumPlugin()

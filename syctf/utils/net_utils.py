"""Small HTTP/OSINT networking helpers shared by SYCTF modules."""

from __future__ import annotations

import re
from typing import Any

import httpx

DEFAULT_HEADERS = {
    "User-Agent": "SYCTF-OSINT/0.2 (+https://github.com/SYCO7/SYCTF)",
    "Accept": "application/json, text/plain, */*",
}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def valid_domain(raw: str) -> str:
    """Normalize and validate a registrable domain; raise ValueError if bad."""

    value = (raw or "").strip().lower()
    value = re.sub(r"^[a-z]+://", "", value)      # drop scheme
    value = value.split("/", 1)[0]                 # drop path
    value = value.split("@", 1)[-1]                # drop userinfo
    value = value.split(":", 1)[0]                 # drop port
    if not _DOMAIN_RE.match(value):
        raise ValueError(f"invalid domain: {raw!r}")
    return value


def http_get(
    url: str,
    *,
    timeout: float = 12.0,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    follow_redirects: bool = True,
) -> httpx.Response | None:
    """GET a URL, returning the response or None on any transport error."""

    merged = dict(DEFAULT_HEADERS)
    if headers:
        merged.update(headers)
    try:
        return httpx.get(
            url,
            params=params,
            headers=merged,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )
    except httpx.HTTPError:
        return None


def http_json(
    url: str,
    *,
    timeout: float = 12.0,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> Any | None:
    """GET a URL and parse JSON, or None on error / non-JSON / non-2xx."""

    response = http_get(url, timeout=timeout, params=params, headers=headers)
    if response is None or response.status_code >= 400:
        return None
    try:
        return response.json()
    except ValueError:
        return None

"""Input validation helpers used by commands and plugins."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse


def validate_url(url: str) -> str:
    """Validate and normalize a URL string."""

    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL must start with http:// or https://")
    if not parsed.netloc:
        raise ValueError("URL must include a valid host")
    return url.strip()


def validate_port_range(start_port: int, end_port: int) -> tuple[int, int]:
    """Validate a TCP port range."""

    if start_port < 1 or start_port > 65535:
        raise ValueError("start-port must be between 1 and 65535")
    if end_port < 1 or end_port > 65535:
        raise ValueError("end-port must be between 1 and 65535")
    if start_port > end_port:
        raise ValueError("start-port must be less than or equal to end-port")
    return start_port, end_port


def validate_hostname(hostname: str) -> str:
    """Validate host/IP values for network scanning."""

    candidate = hostname.strip()
    if not candidate:
        raise ValueError("Host cannot be empty")
    if len(candidate) > 255:
        raise ValueError("Host value is too long")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", candidate):
        raise ValueError("Host contains unsupported characters")
    return candidate


def validate_existing_file(path_value: str) -> Path:
    """Validate that a file exists on disk."""

    file_path = Path(path_value).expanduser().resolve()
    if not file_path.exists() or not file_path.is_file():
        raise ValueError(f"Wordlist file does not exist: {file_path}")
    return file_path

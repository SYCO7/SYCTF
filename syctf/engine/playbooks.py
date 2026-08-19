"""Deterministic per-category playbooks and category detection.

The engine always runs a cheap deterministic pass first (grounded in real
bytes) before spending any LLM tokens. Playbooks list the *built-in* collector
steps to run; ``RECOMMENDED_MODULES`` points the operator (and later phases) at
the matching SYCTF modules for deeper work.
"""

from __future__ import annotations

from pathlib import Path

# Built-in collector step names the executor knows how to run.
CATEGORY_PLAYBOOKS: dict[str, list[str]] = {
    "crypto":    ["identify", "classify-text", "auto-decode", "strings"],
    "rev":       ["identify", "entropy", "strings", "hashes"],
    "pwn":       ["identify", "strings", "entropy"],
    "web":       ["classify-text", "strings"],
    "forensics": ["identify", "entropy", "strings", "hashes"],
    "mobile":    ["identify", "strings", "entropy"],
    "cloud":     ["classify-text", "strings"],
    "osint":     ["classify-text"],
    "misc":      ["identify", "classify-text", "strings"],
    "unknown":   ["identify", "entropy", "strings", "classify-text"],
}

# Existing SYCTF modules to reach for next, per category (menu keys).
RECOMMENDED_MODULES: dict[str, list[str]] = {
    "crypto":    ["crypto/rsa-attacks", "crypto/xor-tools", "crypto/auto-decode", "misc/smart-decode", "crypto/hash-identifier"],
    "rev":       ["rev/triage", "rev/strings-analyzer", "pwn/elf-analyze"],
    "pwn":       ["pwn/rop-finder", "pwn/fmtstr", "pwn/elf-analyze", "pwn/cyclic", "pwn/offset", "ai/exploit"],
    "web":       ["web/sqli-probe", "web/xss-probe", "web/lfi-probe", "web/jwt-tool", "web/quick-recon", "web/dir-bruteforce", "osint/subdomains"],
    "forensics": ["forensics/stegano", "forensics/zip-crack", "forensics/pcap-extract", "rev/strings-analyzer", "misc/smart-decode"],
    "mobile":    ["mobile/apk-info", "mobile/apk-secrets", "mobile/dex-strings"],
    "cloud":     ["cloud/cloud-keys", "cloud/s3-enum", "cloud/imds-ssrf"],
    "osint":     ["osint/subdomains", "osint/dns-recon", "osint/whois", "osint/wayback", "osint/username-enum"],
    "misc":      ["misc/smart-decode", "crypto/auto-decode"],
    "unknown":   ["rev/triage", "misc/smart-decode"],
}

_EXT_CATEGORY = {
    ".zip": "forensics", ".pcap": "forensics", ".pcapng": "forensics",
    ".png": "forensics", ".jpg": "forensics", ".jpeg": "forensics", ".wav": "forensics",
    ".apk": "mobile", ".ipa": "mobile", ".dex": "mobile",
    ".jar": "rev", ".exe": "rev", ".elf": "pwn", ".so": "rev",
    ".php": "web", ".js": "web", ".html": "web", ".jsp": "web",
    ".pem": "crypto", ".pub": "crypto", ".enc": "crypto",
}

_MAGIC_CATEGORY = {
    "ELF executable": "pwn",
    "PE/DOS executable": "rev",
    "Android DEX": "mobile",
    "ZIP/APK/JAR archive": "forensics",
    "PNG image": "forensics",
    "JPEG image": "forensics",
    "PDF document": "forensics",
    "PEM / key material": "crypto",
}


def playbook_for(category: str) -> list[str]:
    """Return the built-in step list for a category."""

    return CATEGORY_PLAYBOOKS.get(category, CATEGORY_PLAYBOOKS["unknown"])


def detect_category(*, kind: str, file_type: str | None = None, path: Path | None = None, text: str = "") -> str:
    """Cheap deterministic category guess before any LLM call."""

    if kind == "url" or (kind == "host"):
        return "web"
    if file_type and file_type in _MAGIC_CATEGORY:
        return _MAGIC_CATEGORY[file_type]
    if path is not None:
        ext = path.suffix.lower()
        if ext in _EXT_CATEGORY:
            return _EXT_CATEGORY[ext]
    if kind == "text" and text:
        return "crypto"
    return "unknown"

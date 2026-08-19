"""Hardcoded-secret detection shared by mobile / cloud / forensics modules."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

# name -> (compiled pattern, needs_entropy_gate)
_PATTERNS: dict[str, tuple[re.Pattern[str], bool]] = {
    "AWS Access Key ID": (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), False),
    "AWS Secret Key": (re.compile(r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]"), False),
    "Google API Key": (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), False),
    "Google OAuth Client": (re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"), False),
    "GCP Service Account": (re.compile(r'"type"\s*:\s*"service_account"'), False),
    "Firebase URL": (re.compile(r"\bhttps://[a-z0-9-]+\.firebaseio\.com\b"), False),
    "Slack Token": (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), False),
    "GitHub Token": (re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), False),
    "Stripe Live Key": (re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b"), False),
    "SendGrid Key": (re.compile(r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b"), False),
    "Twilio SID": (re.compile(r"\bSK[0-9a-fA-F]{32}\b"), False),
    "JWT": (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), False),
    "Private Key Block": (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), False),
    "Azure Storage Key": (re.compile(r"AccountKey=[0-9A-Za-z+/=]{40,}"), False),
    "Generic Secret Assignment": (
        re.compile(r"(?i)(?:api[_-]?key|secret|token|password|passwd|auth)\s*[=:]\s*['\"]([^'\"\s]{8,64})['\"]"),
        True,
    ),
}


@dataclass(slots=True)
class SecretHit:
    """One detected secret."""

    kind: str
    value: str
    context: str = ""


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def scan_secrets(text: str, *, source: str = "", min_entropy: float = 3.0) -> list[SecretHit]:
    """Return de-duplicated secret hits found in ``text``."""

    seen: set[tuple[str, str]] = set()
    hits: list[SecretHit] = []
    for kind, (pattern, gated) in _PATTERNS.items():
        for match in pattern.finditer(text or ""):
            captured = match.group(1) if match.groups() else match.group(0)
            value = captured.strip()
            if gated and shannon_entropy(value) < min_entropy:
                continue
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            hits.append(SecretHit(kind=kind, value=value[:120], context=source))
    return hits

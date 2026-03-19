"""Challenge category detection for SYCTF AI mode."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.panel import Panel
from syctf.ai.client import get_ollama_client

CATEGORIES = {"pwn", "crypto", "web", "rev", "misc", "forensics"}
AI_TIMEOUT_SECONDS = 12.0

DETECTION_PROMPT = """
You are a CTF category classifier.

Allowed categories:
- pwn
- crypto
- web
- rev
- misc
- forensics

Given a challenge description, output JSON only using this schema:
{
  "category": "one of allowed categories",
  "confidence": 0.0 to 1.0,
  "reasoning": "short reason"
}

Rules:
- Pick exactly one category.
- Confidence must be numeric and conservative.
- Do not include markdown or extra keys.
""".strip()


@dataclass(slots=True)
class CategoryDetection:
    """Structured category detection result."""

    category: str
    confidence: float
    reasoning: str

    def as_dict(self) -> dict[str, Any]:
        """Return detector output in JSON-serializable shape."""

        return {
            "category": self.category,
            "confidence": round(self.confidence, 2),
            "reasoning": self.reasoning,
        }


def _normalize_result(category: str, confidence: float, reasoning: str) -> CategoryDetection:
    """Normalize values and enforce category schema."""

    cleaned_category = str(category).strip().lower()
    if cleaned_category not in CATEGORIES:
        cleaned_category = "misc"

    cleaned_confidence = float(confidence)
    if cleaned_confidence < 0:
        cleaned_confidence = 0.0
    if cleaned_confidence > 1:
        cleaned_confidence = 1.0

    cleaned_reasoning = str(reasoning).strip() or "fallback classification"
    return CategoryDetection(
        category=cleaned_category,
        confidence=cleaned_confidence,
        reasoning=cleaned_reasoning,
    )


def _heuristic_detect(text: str) -> CategoryDetection | None:
    """Fast mode heuristic fallback for obvious challenge signals."""

    lowered = text.lower()

    if "base64" in lowered:
        return _normalize_result("crypto", 0.95, "contains base64 indicator")
    if "binary" in lowered:
        return _normalize_result("pwn", 0.88, "mentions binary target")
    if ".pcap" in lowered:
        return _normalize_result("forensics", 0.97, "mentions .pcap artifact")

    # Additional low-cost keyword boosts for better defaults.
    if any(k in lowered for k in ["sqli", "xss", "lfi", "ssrf", "http", "cookie"]):
        return _normalize_result("web", 0.75, "web exploitation keywords detected")
    if any(k in lowered for k in ["disassemble", "ghidra", "ida", "decompile", "opcode"]):
        return _normalize_result("rev", 0.78, "reverse-engineering keywords detected")
    if any(k in lowered for k in ["packet", "pcapng", "wireshark", "memory dump", "forensic"]):
        return _normalize_result("forensics", 0.8, "forensics artifacts detected")
    if any(k in lowered for k in ["rsa", "xor", "aes", "sha", "hash", "cipher"]):
        return _normalize_result("crypto", 0.74, "cryptography keywords detected")
    if any(k in lowered for k in ["bof", "buffer overflow", "canary", "rop", "elf"]):
        return _normalize_result("pwn", 0.8, "binary exploitation keywords detected")

    return None


def _extract_json_block(raw: str) -> dict[str, Any] | None:
    """Extract first JSON object from model output."""

    candidate = raw.strip()
    if candidate.startswith("{") and candidate.endswith("}"):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            return None

    match = re.search(r"\{.*\}", candidate, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def detect_category(text: str, model: str = "deepseek-coder:6.7b") -> dict[str, Any]:
    """Detect challenge category using heuristics first, then Ollama LLM."""

    payload = text.strip()
    if not payload:
        return _normalize_result("misc", 0.0, "empty challenge description").as_dict()

    heuristic = _heuristic_detect(payload)
    if heuristic and heuristic.confidence >= 0.85:
        return heuristic.as_dict()

    try:
        client = get_ollama_client(timeout=AI_TIMEOUT_SECONDS)
        response = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": DETECTION_PROMPT},
                {"role": "user", "content": payload},
            ],
        )
        content = response.get("message", {}).get("content", "")
        parsed = _extract_json_block(content)
        if parsed is None:
            if heuristic:
                return heuristic.as_dict()
            return _normalize_result("misc", 0.35, "model returned non-JSON output").as_dict()

        result = _normalize_result(
            category=parsed.get("category", "misc"),
            confidence=parsed.get("confidence", 0.4),
            reasoning=parsed.get("reasoning", "model-based classification"),
        )
        return result.as_dict()
    except Exception as exc:  # noqa: BLE001
        if heuristic:
            return heuristic.as_dict()
        return _normalize_result(
            "misc",
            0.3,
            f"LLM unavailable; defaulted to misc ({type(exc).__name__}: {exc})",
        ).as_dict()


def suggested_workflow(category: str) -> list[str]:
    """Return category-specific suggested SYCTF commands."""

    mapping = {
        "pwn": [
            "syctf pwn-helper elf-analyze ./chall",
            "syctf pwn-helper cyclic generate --length 300",
            "syctf shell  # then: ai exploit ./chall",
        ],
        "crypto": [
            "syctf crypto-helper hash-ident --hash <hash>",
            "syctf crypto-helper caesar-brute --text <cipher>",
            "syctf misc smart-decode --text <blob>",
        ],
        "web": [
            "syctf recon http-headers --url <target>",
            "syctf recon robots --url <target>",
            "syctf web-helper dir-bruteforce --url <target>",
        ],
        "rev": [
            "syctf misc env-check",
            "syctf shell  # then: ai recon-plan",
            "syctf misc smart-decode --text <obfuscated_blob>",
        ],
        "forensics": [
            "syctf misc smart-decode --text <artifact_string>",
            "syctf misc env-check --tools strings binwalk",
            "syctf shell  # then: ai decode",
        ],
        "misc": [
            "syctf misc smart-decode --text <input>",
            "syctf shell  # then: ai recon-plan",
            "syctf ai-setup",
        ],
    }
    return mapping.get(category, mapping["misc"])


def render_detection(console: Console, detection: dict[str, Any]) -> None:
    """Render detected category and confidence in a rich panel."""

    category = str(detection.get("category", "misc")).upper()
    confidence = float(detection.get("confidence", 0.0))
    reasoning = str(detection.get("reasoning", ""))

    if confidence >= 0.85:
        confidence_text = "HIGH"
        color = "green"
    elif confidence >= 0.6:
        confidence_text = "MEDIUM"
        color = "yellow"
    else:
        confidence_text = "LOW"
        color = "red"

    body = (
        f"Detected Category: [bold {color}]{category}[/bold {color}]\n"
        f"Confidence: [bold {color}]{confidence_text}[/bold {color}] ({confidence:.2f})\n"
        f"Reasoning: {reasoning}"
    )
    console.print(Panel(body, title="Challenge Classification", border_style=color))

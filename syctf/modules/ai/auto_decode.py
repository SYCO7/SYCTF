"""Heuristic-first auto decode pipeline with optional LLM fallback."""

from __future__ import annotations

import base64
import json
import math
import re
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from syctf.ai.client import get_ollama_client
from syctf.core.workspace_state import workspace_output_dir

KNOWN_FLAG_PREFIXES = (
    "picoCTF{",
    "flag{",
    "HTB{",
    "CTF{",
)

SYSTEM_PROMPT = (
    "You are an elite CTF exploitation assistant. Always output working Python scripts "
    "to decode multilayer ciphertext. Avoid tutorials."
)

ENGLISH_WORDS = {
    "the",
    "and",
    "this",
    "that",
    "with",
    "from",
    "flag",
    "challenge",
    "token",
    "admin",
    "password",
    "hello",
    "world",
    "http",
    "decoded",
}

MAX_INPUT_CHARS = 100_000
DEFAULT_MAX_DEPTH = 4
DEFAULT_TOP = 8
DEFAULT_BEAM = 24
DEFAULT_LLM_THRESHOLD = 0.72
DEFAULT_MODEL = "deepseek-coder:6.7b"


@dataclass(slots=True)
class TransformStep:
    """One transformation step in a decode chain."""

    name: str
    argument: str | None = None

    def label(self) -> str:
        """Return readable step label for terminal rendering."""

        if self.argument is None:
            return self.name
        return f"{self.name}({self.argument})"


@dataclass(slots=True)
class ScoreBreakdown:
    """Detailed score components for one candidate output."""

    readable_english: float
    braces_presence: float
    known_flag_prefix: float
    entropy_reduction: float
    total: float


@dataclass(slots=True)
class Candidate:
    """One decoded candidate with associated pipeline and score."""

    text: str
    pipeline: list[TransformStep]
    score: ScoreBreakdown

    def pipeline_label(self) -> str:
        """Serialize pipeline into arrow-separated representation."""

        if not self.pipeline:
            return "input"
        return "input -> " + " -> ".join(step.label() for step in self.pipeline)


@dataclass(slots=True)
class AutoDecodeResult:
    """Result envelope for auto decode execution."""

    input_text: str
    hints: list[str]
    ranked: list[Candidate]
    best: Candidate
    llm_used: bool
    llm_script: str | None


def _normalize_input(raw: str) -> str:
    """Normalize cipher input and enforce size constraints."""

    cleaned = raw.replace("\x00", "").lstrip("\ufeff").strip()
    if not cleaned:
        raise ValueError("Cipher input cannot be empty")
    if len(cleaned) > MAX_INPUT_CHARS:
        raise ValueError(f"Input exceeds safe limit ({MAX_INPUT_CHARS} chars)")
    return cleaned


def _safe_to_text(data: bytes) -> str:
    """Decode bytes to text safely with UTF-8 fallback."""

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def _is_likely_base64(text: str) -> bool:
    payload = text.strip()
    if len(payload) < 8:
        return False
    if re.search(r"[^A-Za-z0-9+/=]", payload):
        return False
    return len(payload) % 4 in {0, 2, 3}


def _is_likely_hex(text: str) -> bool:
    payload = "".join(text.split())
    return len(payload) >= 8 and len(payload) % 2 == 0 and all(ch in string.hexdigits for ch in payload)


def _decode_base64(text: str) -> str:
    payload = text.strip()
    padded = payload + ("=" * ((4 - len(payload) % 4) % 4))
    return _safe_to_text(base64.b64decode(padded.encode("utf-8"), validate=True))


def _decode_hex(text: str) -> str:
    payload = "".join(text.split())
    if len(payload) % 2 != 0:
        raise ValueError("Odd hex length")
    return _safe_to_text(bytes.fromhex(payload))


def _reverse(text: str) -> str:
    return text[::-1]


def _caesar_shift(text: str, shift: int) -> str:
    out_chars: list[str] = []
    for char in text:
        if "a" <= char <= "z":
            out_chars.append(chr((ord(char) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= char <= "Z":
            out_chars.append(chr((ord(char) - ord("A") + shift) % 26 + ord("A")))
        else:
            out_chars.append(char)
    return "".join(out_chars)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    score = 0.0
    for value in counts.values():
        probability = value / total
        score -= probability * math.log2(probability)
    return score


def _readable_english_score(text: str) -> float:
    if not text:
        return 0.0

    printable = sum(1 for char in text if char in "\n\r\t" or 32 <= ord(char) <= 126)
    printable_ratio = printable / max(1, len(text))

    words = [token.strip(".,:;!?()[]{}<>'\"") for token in text.lower().split()]
    words = [token for token in words if token]
    if words:
        hits = sum(1 for token in words if token in ENGLISH_WORDS)
        lexical = hits / max(1, min(40, len(words)))
    else:
        lexical = 0.0

    alpha_space = sum(1 for char in text if char.isalpha() or char.isspace()) / max(1, len(text))
    combined = (printable_ratio * 0.55) + (lexical * 0.25) + (alpha_space * 0.20)
    return max(0.0, min(1.0, combined))


def _braces_score(text: str) -> float:
    has_open = "{" in text
    has_close = "}" in text
    if has_open and has_close:
        return 1.0
    if has_open or has_close:
        return 0.45
    return 0.0


def _flag_prefix_score(text: str) -> float:
    lowered = text.lower()
    for prefix in KNOWN_FLAG_PREFIXES:
        pref = prefix.lower()
        if lowered.startswith(pref):
            return 1.0
        if pref in lowered:
            return 0.75
    return 0.0


def _score_candidate(text: str, input_entropy: float) -> ScoreBreakdown:
    readable = _readable_english_score(text)
    braces = _braces_score(text)
    prefix = _flag_prefix_score(text)

    current_entropy = _entropy(text[:8192])
    if input_entropy <= 0:
        entropy_reduction = 0.0
    else:
        entropy_reduction = max(0.0, input_entropy - current_entropy) / input_entropy
        entropy_reduction = min(1.0, entropy_reduction)

    total = (readable * 0.45) + (braces * 0.12) + (prefix * 0.33) + (entropy_reduction * 0.10)
    return ScoreBreakdown(
        readable_english=round(readable, 4),
        braces_presence=round(braces, 4),
        known_flag_prefix=round(prefix, 4),
        entropy_reduction=round(entropy_reduction, 4),
        total=round(total, 4),
    )


def detect_cipher_hints(cipher: str) -> list[str]:
    """Return cheap preflight hints before transform exploration."""

    hints: list[str] = []
    payload = cipher.strip()

    if _is_likely_base64(payload):
        hints.append("base64-like alphabet detected")
    if _is_likely_hex(payload):
        hints.append("hex-like byte stream detected")
    if "}{" in payload or payload.endswith("{"):
        hints.append("reversal pattern detected (possible reversed flag)")
    if any(prefix.lower() in payload.lower() for prefix in ("picoctf", "htb", "flag")):
        hints.append("flag marker fragments already present")

    alpha_ratio = sum(1 for char in payload if char.isalpha()) / max(1, len(payload))
    if alpha_ratio >= 0.65:
        hints.append("alphabetic payload; Caesar/ROT candidates enabled")

    if not hints:
        hints.append("no strong cipher fingerprint detected")
    return hints


def _candidate_ops(text: str) -> list[tuple[TransformStep, str]]:
    """Generate transform outputs for one search frontier item."""

    outputs: list[tuple[TransformStep, str]] = []

    try:
        if _is_likely_base64(text):
            decoded = _decode_base64(text)
            if decoded and decoded != text:
                outputs.append((TransformStep("base64"), decoded))
    except Exception:
        pass

    try:
        if _is_likely_hex(text):
            decoded = _decode_hex(text)
            if decoded and decoded != text:
                outputs.append((TransformStep("hex"), decoded))
    except Exception:
        pass

    reversed_text = _reverse(text)
    if reversed_text != text:
        outputs.append((TransformStep("reverse"), reversed_text))

    alpha_ratio = sum(1 for char in text if char.isalpha()) / max(1, len(text))
    if alpha_ratio >= 0.45 and len(text) <= 8000:
        for shift in range(1, 26):
            shifted = _caesar_shift(text, shift)
            if shifted != text:
                outputs.append((TransformStep("caesar", str(shift)), shifted))

    return outputs


def rank_candidates(
    cipher: str,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    top_n: int = DEFAULT_TOP,
    beam_width: int = DEFAULT_BEAM,
) -> list[Candidate]:
    """Explore transform chains and return ranked candidates."""

    baseline = _normalize_input(cipher)
    input_entropy = _entropy(baseline[:8192])

    root = Candidate(text=baseline, pipeline=[], score=_score_candidate(baseline, input_entropy))
    ranked: list[Candidate] = [root]
    frontier: list[Candidate] = [root]
    seen: set[str] = {baseline}

    depth_limit = max(1, min(8, int(max_depth)))
    beam = max(4, min(64, int(beam_width)))

    for _ in range(depth_limit):
        new_items: list[Candidate] = []
        for item in frontier:
            for step, transformed in _candidate_ops(item.text):
                if transformed in seen:
                    continue
                seen.add(transformed)
                pipeline = [*item.pipeline, step]
                new_items.append(
                    Candidate(
                        text=transformed,
                        pipeline=pipeline,
                        score=_score_candidate(transformed, input_entropy),
                    )
                )

        if not new_items:
            break

        dedup: dict[str, Candidate] = {}
        for item in new_items:
            current = dedup.get(item.text)
            if current is None or item.score.total > current.score.total:
                dedup[item.text] = item

        frontier = sorted(dedup.values(), key=lambda item: item.score.total, reverse=True)[:beam]
        ranked.extend(frontier)

    final = sorted(ranked, key=lambda item: item.score.total, reverse=True)
    return final[: max(1, min(20, int(top_n)))]


def _extract_script_payload(text: str) -> str:
    """Extract Python code from markdown fence if present."""

    fenced = re.search(r"```(?:python)?\n(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        return fenced.group(1).strip()
    return text.strip()


def request_llm_script(
    *,
    cipher: str,
    hints: list[str],
    candidates: list[Candidate],
    model: str,
) -> str | None:
    """Request script-only decoder from Ollama when heuristic confidence is weak."""

    compact_candidates = [
        {
            "pipeline": item.pipeline_label(),
            "score": item.score.total,
            "preview": item.text[:180],
        }
        for item in candidates[:5]
    ]

    user_prompt = (
        "Build a Python3 script that decodes this ciphertext and prints the best final plaintext. "
        "Use a deterministic transform chain, no prose. Output code only.\n\n"
        f"cipher={cipher}\n"
        f"hints={json.dumps(hints, ensure_ascii=True)}\n"
        f"ranked_candidates={json.dumps(compact_candidates, ensure_ascii=True)}"
    )

    try:
        client = get_ollama_client(timeout=25.0)
        response = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
        content = str(response.get("message", {}).get("content", "")).strip()
        if not content:
            return None
        payload = _extract_script_payload(content)
        if "def " not in payload and "import " not in payload:
            return None
        return payload
    except Exception:
        return None


def generate_replay_script(cipher: str, candidate: Candidate) -> str:
    """Generate deterministic script that replays discovered transform pipeline."""

    lines: list[str] = [
        "#!/usr/bin/env python3",
        "import base64",
        "",
        "INPUT = " + repr(cipher),
        "",
        "",
        "def caesar_shift(text: str, shift: int) -> str:",
        "    out = []",
        "    for ch in text:",
        "        if 'a' <= ch <= 'z':",
        "            out.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))",
        "        elif 'A' <= ch <= 'Z':",
        "            out.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))",
        "        else:",
        "            out.append(ch)",
        "    return ''.join(out)",
        "",
        "",
        "def b64_decode(text: str) -> str:",
        "    payload = text.strip()",
        "    payload += '=' * ((4 - len(payload) % 4) % 4)",
        "    data = base64.b64decode(payload.encode('utf-8'), validate=True)",
        "    try:",
        "        return data.decode('utf-8')",
        "    except UnicodeDecodeError:",
        "        return data.decode('latin-1', errors='replace')",
        "",
        "",
        "def main() -> None:",
        "    text = INPUT",
    ]

    for step in candidate.pipeline:
        if step.name == "base64":
            lines.append("    text = b64_decode(text)")
        elif step.name == "hex":
            lines.extend(
                [
                    "    payload = ''.join(text.split())",
                    "    text = bytes.fromhex(payload).decode('utf-8', errors='replace')",
                ]
            )
        elif step.name == "reverse":
            lines.append("    text = text[::-1]")
        elif step.name == "caesar":
            shift = int(step.argument or "0")
            lines.append(f"    text = caesar_shift(text, {shift})")

    lines.extend(
        [
            "    print(text)",
            "",
            "",
            "if __name__ == '__main__':",
            "    main()",
            "",
        ]
    )
    return "\n".join(lines)


def _render_hints(console: Console, hints: list[str]) -> None:
    body = "\n".join(f"- {item}" for item in hints)
    console.print(Panel(body, title="Detected Cipher Hints", border_style="cyan"))


def _render_candidates(console: Console, ranked: list[Candidate]) -> None:
    table = Table(title="Transform Pipeline Ranking")
    table.add_column("Rank", style="cyan", no_wrap=True)
    table.add_column("Score", style="green", no_wrap=True)
    table.add_column("Pipeline", style="magenta")
    table.add_column("Preview", style="white")

    for idx, item in enumerate(ranked, start=1):
        table.add_row(
            str(idx),
            f"{item.score.total:.4f}",
            item.pipeline_label(),
            item.text[:90].replace("\n", "\\n"),
        )
    console.print(table)


def _render_best(console: Console, best: Candidate) -> None:
    breakdown = (
        f"readable_english={best.score.readable_english:.4f} | "
        f"braces={best.score.braces_presence:.4f} | "
        f"flag_prefix={best.score.known_flag_prefix:.4f} | "
        f"entropy_reduction={best.score.entropy_reduction:.4f}"
    )
    console.print(
        Panel(
            f"Pipeline: {best.pipeline_label()}\n"
            f"Score: {best.score.total:.4f}\n"
            f"Components: {breakdown}\n\n"
            f"{best.text[:4000]}",
            title="Best Candidate",
            border_style="green",
        )
    )


def _persist_script(script: str, cache: dict[str, Any] | None) -> Path | None:
    """Persist generated decoder script into workspace decoded directory."""

    if cache is None:
        return None
    out_dir = workspace_output_dir("decoded", cache)
    if out_dir is None:
        return None
    path = out_dir / "auto_decode_solution.py"
    path.write_text(script, encoding="utf-8")
    return path


def auto_decode(
    cipher: str,
    *,
    model: str = DEFAULT_MODEL,
    max_depth: int = DEFAULT_MAX_DEPTH,
    top_n: int = DEFAULT_TOP,
    llm_threshold: float = DEFAULT_LLM_THRESHOLD,
) -> AutoDecodeResult:
    """Run heuristic-first decode flow and conditionally request LLM script."""

    normalized = _normalize_input(cipher)
    hints = detect_cipher_hints(normalized)
    ranked = rank_candidates(normalized, max_depth=max_depth, top_n=top_n)
    best = ranked[0]

    threshold = max(0.0, min(1.0, llm_threshold))
    llm_script: str | None = None
    llm_used = False

    if best.score.total < threshold:
        llm_used = True
        llm_script = request_llm_script(
            cipher=normalized,
            hints=hints,
            candidates=ranked,
            model=model,
        )

    return AutoDecodeResult(
        input_text=normalized,
        hints=hints,
        ranked=ranked,
        best=best,
        llm_used=llm_used,
        llm_script=llm_script,
    )


def run_auto_decode_command(
    cipher: str,
    *,
    console: Console,
    cache: dict[str, Any] | None = None,
    model: str = DEFAULT_MODEL,
    max_depth: int = DEFAULT_MAX_DEPTH,
    top_n: int = DEFAULT_TOP,
    llm_threshold: float = DEFAULT_LLM_THRESHOLD,
    script: bool = False,
) -> int:
    """Execute CLI command flow for syctf auto-decode."""

    result = auto_decode(
        cipher,
        model=model,
        max_depth=max_depth,
        top_n=top_n,
        llm_threshold=llm_threshold,
    )

    _render_hints(console, result.hints)
    _render_candidates(console, result.ranked)
    _render_best(console, result.best)

    if result.llm_used:
        if result.llm_script:
            console.print(
                Panel(
                    result.llm_script[:5000],
                    title="Low Confidence: LLM Script Suggestion",
                    border_style="yellow",
                )
            )
        else:
            console.print("[yellow]Low confidence and LLM fallback returned no script.[/yellow]")

    if script:
        replay_script = generate_replay_script(result.input_text, result.best)
        path = _persist_script(replay_script, cache)
        console.print(
            Panel(
                replay_script[:5000],
                title="Auto-Generated Repro Script",
                border_style="magenta",
            )
        )
        if path is not None:
            console.print(f"[green]Saved script:[/green] {path}")

    if cache is not None:
        cache["auto_decode_result"] = {
            "hints": result.hints,
            "best": result.best.text,
            "best_pipeline": result.best.pipeline_label(),
            "best_score": result.best.score.total,
            "ranked": [
                {
                    "score": item.score.total,
                    "pipeline": item.pipeline_label(),
                    "preview": item.text[:200],
                }
                for item in result.ranked
            ],
            "llm_used": result.llm_used,
            "llm_script": (result.llm_script or "")[:4000],
        }

    return 0

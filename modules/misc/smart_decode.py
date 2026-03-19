"""Production-grade recursive decoding engine for CTF workflows."""

from __future__ import annotations

import argparse
import base64
import codecs
import hashlib
import json
import math
import re
import string
import sys
import time
import urllib.parse
import zlib
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from syctf.core.cache_store import cache_key, load_json_cache, save_json_cache
from syctf.core.workspace_state import workspace_output_dir

name = "smart-decode"
description = "Recursive layered decoder with heuristic scoring"

MAX_DEPTH_DEFAULT = 6
MAX_INPUT_CHARS = 100_000
MAX_DECOMPRESSED_BYTES = 1_000_000
RECURSION_TIMEOUT_SECONDS = 4.0
XOR_SCORE_SAMPLE = 8192
TOP_CANDIDATES = 5

FLAG_REGEX = re.compile(r"(CTF\{|picoCTF\{|HTB\{)", re.IGNORECASE)
ENGLISH_WORDS = {
    "the",
    "and",
    "that",
    "this",
    "with",
    "you",
    "from",
    "flag",
    "admin",
    "login",
    "token",
    "password",
    "challenge",
    "exploit",
    "hello",
    "world",
}


class Candidate:
    """Decoded candidate representation with score metadata."""

    def __init__(self, method: str, text: str, score: float, key: int | None = None) -> None:
        self.method = method
        self.text = text
        self.score = score
        self.key = key

    def as_dict(self) -> dict[str, Any]:
        """Return serializable candidate object."""

        out: dict[str, Any] = {
            "method": self.method,
            "score": round(self.score, 4),
            "text": self.text[:500],
        }
        if self.key is not None:
            out["key"] = self.key
        return out


def detect_base64(text: str) -> bool:
    """Fast heuristic detector for base64-like payloads."""

    payload = text.strip()
    if len(payload) < 8:
        return False
    if re.search(r"[^A-Za-z0-9+/=]", payload):
        return False
    return len(payload) % 4 in {0, 2, 3}


def detect_hex(text: str) -> bool:
    """Detect if string likely represents hex bytes."""

    payload = "".join(text.split())
    return len(payload) >= 8 and len(payload) % 2 == 0 and all(ch in string.hexdigits for ch in payload)


def detect_jwt(text: str) -> bool:
    """Detect if string looks like a JWT token."""

    parts = text.strip().split(".")
    if len(parts) < 2:
        return False
    return all(re.fullmatch(r"[A-Za-z0-9_-]+", part or "") for part in parts[:2])


def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy over characters."""

    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def printable_ratio(text: str) -> float:
    """Calculate printable ratio for decoded text quality."""

    if not text:
        return 0.0
    printable = 0
    for ch in text:
        if ch in "\n\r\t":
            printable += 1
        elif 32 <= ord(ch) <= 126:
            printable += 1
    return printable / max(1, len(text))


def english_ratio(text: str) -> float:
    """Estimate English-likeness based on vocabulary hits and alphabet ratio."""

    if not text:
        return 0.0
    lowered = text.lower()
    words = [w.strip(".,:;!?()[]{}<>'\"") for w in lowered.split()]
    words = [w for w in words if w]
    if not words:
        return 0.0
    hits = sum(1 for w in words if w in ENGLISH_WORDS)
    lexical = hits / max(1, min(40, len(words)))
    alpha = sum(ch.isalpha() or ch.isspace() for ch in lowered) / max(1, len(lowered))
    return min(1.0, (lexical * 0.65) + (alpha * 0.35))


def score_text(text: str, *, previous_entropy: float | None = None) -> float:
    """Heuristic score based on readability, language, flags, and entropy trend."""

    p_ratio = printable_ratio(text)
    e_ratio = english_ratio(text)
    entropy = shannon_entropy(text[:8192])

    flag_bonus = 0.22 if FLAG_REGEX.search(text) else 0.0
    entropy_bonus = 0.0
    if previous_entropy is not None and entropy < previous_entropy:
        entropy_bonus = min(0.18, (previous_entropy - entropy) * 0.05)

    return round((p_ratio * 0.50) + (e_ratio * 0.28) + flag_bonus + entropy_bonus, 4)


def _normalize_input(raw: str) -> str:
    """Normalize and enforce input size limits."""

    cleaned = raw.replace("\x00", "").lstrip("\ufeff").strip()
    if not cleaned:
        raise ValueError("Input cannot be empty")
    if len(cleaned) > MAX_INPUT_CHARS:
        raise ValueError(f"Input exceeds safe limit ({MAX_INPUT_CHARS} chars)")
    return cleaned


def _safe_to_text(data: bytes) -> str:
    """Convert bytes to text safely with size check."""

    if len(data) > MAX_DECOMPRESSED_BYTES:
        raise ValueError("Decoded binary exceeds safe limit")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def _safe_decompress(data: bytes, wbits: int) -> bytes:
    """Safely decompress data while guarding against zip bombs."""

    obj = zlib.decompressobj(wbits)
    out = obj.decompress(data, MAX_DECOMPRESSED_BYTES + 1)
    if len(out) > MAX_DECOMPRESSED_BYTES:
        raise ValueError("Decompression output too large")
    out += obj.flush(MAX_DECOMPRESSED_BYTES + 1 - len(out))
    if len(out) > MAX_DECOMPRESSED_BYTES:
        raise ValueError("Decompression output too large")
    return out


def _decode_base64(text: str) -> str:
    payload = text.strip()
    padded = payload + ("=" * ((4 - len(payload) % 4) % 4))
    data = base64.b64decode(padded.encode("utf-8"), validate=True)
    return _safe_to_text(data)


def _decode_base32(text: str) -> str:
    payload = text.strip().upper()
    padded = payload + ("=" * ((8 - len(payload) % 8) % 8))
    data = base64.b32decode(padded.encode("utf-8"), casefold=True)
    return _safe_to_text(data)


def _decode_base85(text: str) -> str:
    data = base64.b85decode(text.strip().encode("utf-8"))
    return _safe_to_text(data)


def _decode_hex(text: str) -> str:
    payload = "".join(text.strip().split())
    if len(payload) % 2 != 0:
        raise ValueError("Odd hex length")
    return _safe_to_text(bytes.fromhex(payload))


def _decode_rot13(text: str) -> str:
    out = codecs.decode(text, "rot_13")
    if out == text:
        raise ValueError("ROT13 no-op")
    return out


def _decode_url(text: str) -> str:
    out = urllib.parse.unquote_plus(text)
    if out == text:
        raise ValueError("URL decode no-op")
    return out


def _decode_gzip(text: str) -> str:
    raw = text.encode("latin-1", errors="ignore")
    return _safe_to_text(_safe_decompress(raw, 16 + zlib.MAX_WBITS))


def _decode_zlib(text: str) -> str:
    raw = text.encode("latin-1", errors="ignore")
    return _safe_to_text(_safe_decompress(raw, zlib.MAX_WBITS))


def _decode_jwt_payload(text: str) -> str:
    parts = text.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Not JWT")
    payload = parts[1]
    padded = payload + ("=" * ((4 - len(payload) % 4) % 4))
    data = base64.urlsafe_b64decode(padded.encode("utf-8"))
    text_payload = _safe_to_text(data)
    try:
        return json.dumps(json.loads(text_payload), ensure_ascii=False)
    except json.JSONDecodeError:
        return text_payload


def xor_bruteforce(text: str, *, previous_entropy: float | None = None, top_n: int = 5) -> list[dict[str, Any]]:
    """Bruteforce single-byte XOR and return top ranked candidates."""

    raw = text.encode("latin-1", errors="ignore")[:XOR_SCORE_SAMPLE]
    if not raw:
        return []

    source = bytearray(raw)
    xor_tables = [bytes((value ^ key for value in range(256))) for key in range(256)]
    best: list[Candidate] = []
    for key in range(256):
        # Fast XOR using byte translation table over a mutable bytearray snapshot.
        translated = source.translate(xor_tables[key])
        out = bytes(translated)
        decoded = out.decode("latin-1", errors="replace")
        score = score_text(decoded, previous_entropy=previous_entropy)
        candidate = Candidate(method="xor-single-byte", text=decoded, score=score, key=key)

        if len(best) < top_n:
            best.append(candidate)
            best.sort(key=lambda item: item.score, reverse=True)
            continue
        if candidate.score > best[-1].score:
            best[-1] = candidate
            best.sort(key=lambda item: item.score, reverse=True)

    return [item.as_dict() for item in best]


DECODER_CHAIN: list[tuple[str, Callable[[str], str], Callable[[str], bool] | None]] = [
    ("base64", _decode_base64, detect_base64),
    ("hex", _decode_hex, detect_hex),
    ("rot13", _decode_rot13, None),
    ("url", _decode_url, None),
    ("base32", _decode_base32, None),
    ("base85", _decode_base85, None),
    ("gzip", _decode_gzip, None),
    ("zlib", _decode_zlib, None),
    ("jwt-payload", _decode_jwt_payload, detect_jwt),
]


def _next_layer_candidates(current: str, previous_entropy: float) -> list[Candidate]:
    """Generate all decoder candidates for one recursion layer."""

    out: list[Candidate] = []
    for method, decoder, detector in DECODER_CHAIN:
        try:
            if detector is not None and not detector(current):
                continue
            decoded = decoder(current)
            if not decoded or decoded == current:
                continue
            score = score_text(decoded, previous_entropy=previous_entropy)
            out.append(Candidate(method=method, text=decoded, score=score))
        except Exception:
            continue

    for candidate in xor_bruteforce(current, previous_entropy=previous_entropy, top_n=TOP_CANDIDATES):
        out.append(
            Candidate(
                method=f"xor-single-byte(key={candidate.get('key')})",
                text=str(candidate.get("text", "")),
                score=float(candidate.get("score", 0.0)),
                key=int(candidate.get("key")) if candidate.get("key") is not None else None,
            )
        )

    out.sort(key=lambda item: item.score, reverse=True)
    return out


def decode_recursive(text: str, *, max_depth: int = MAX_DEPTH_DEFAULT, timeout_seconds: float = RECURSION_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Run iterative recursive decoding until score no longer improves."""

    current = _normalize_input(text)
    seen: set[str] = {current}
    current_score = score_text(current)
    current_entropy = shannon_entropy(current[:8192])
    layers: list[dict[str, Any]] = []
    candidates: list[Candidate] = [Candidate(method="input", text=current, score=current_score)]

    started = time.monotonic()
    depth_limit = max(1, min(20, int(max_depth)))

    for depth in range(1, depth_limit + 1):
        if time.monotonic() - started > timeout_seconds:
            break

        layer_candidates = [c for c in _next_layer_candidates(current, current_entropy) if c.text not in seen]
        if not layer_candidates:
            break

        best = layer_candidates[0]
        if best.score <= current_score + 0.01:
            break

        seen.add(best.text)
        layers.append(
            {
                "layer": depth,
                "method": best.method,
                "score": round(best.score, 4),
                "preview": best.text[:120],
            }
        )
        candidates.extend(layer_candidates[:TOP_CANDIDATES])
        current = best.text
        current_score = best.score
        current_entropy = shannon_entropy(current[:8192])

    dedup: dict[tuple[str, str], Candidate] = {}
    for item in candidates:
        key = (item.method, item.text)
        if key not in dedup or item.score > dedup[key].score:
            dedup[key] = item

    best_candidates = sorted(dedup.values(), key=lambda item: item.score, reverse=True)[:TOP_CANDIDATES]
    return {
        "layers": layers,
        "best": current,
        "candidates": [item.as_dict() for item in best_candidates],
    }


def _read_text_file(path_raw: str) -> str:
    """Read file content with encoding fallbacks."""

    path = Path(path_raw).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise ValueError(f"File not found: {path}")
    if path.stat().st_size > MAX_INPUT_CHARS:
        raise ValueError(f"Input file too large ({MAX_INPUT_CHARS} byte limit)")

    raw = path.read_bytes()
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def _resolve_input(text: str | None, file_path: str | None) -> str:
    """Resolve input from positional text, file, stdin, or interactive prompt."""

    if text and text.strip():
        return text.strip()
    if file_path:
        return _read_text_file(file_path).strip()
    if not sys.stdin.isatty():
        piped = sys.stdin.read().strip()
        if piped:
            return piped
    return input("Encoded input > ").strip()


def _render_result(console: Console, result: dict[str, Any]) -> None:
    """Render layer progression and ranked candidates via rich."""

    layers = result.get("layers", [])
    if layers:
        for layer in layers:
            console.print(
                f"[bold green]Layer {layer.get('layer')}[/bold green] -> "
                f"[cyan]{layer.get('method')}[/cyan] "
                f"score={layer.get('score')}"
            )
    else:
        console.print("[yellow]No higher-scoring transformation found.[/yellow]")

    console.print(
        Panel(
            str(result.get("best", ""))[:4000],
            title="Best Decoded Output",
            border_style="green",
        )
    )

    table = Table(title="Top Candidates")
    table.add_column("Rank", style="cyan", no_wrap=True)
    table.add_column("Method", style="magenta")
    table.add_column("Score", style="green", no_wrap=True)
    table.add_column("Preview", style="white")

    for idx, item in enumerate(result.get("candidates", []), start=1):
        method = str(item.get("method", "unknown"))
        score = str(item.get("score", "0"))
        preview = str(item.get("text", ""))[:90]
        table.add_row(str(idx), method, score, preview)
    console.print(table)


def run(
    text: str | None,
    *,
    context: Any | None = None,
    file_path: str | None = None,
    max_depth: int = MAX_DEPTH_DEFAULT,
) -> dict[str, Any] | int:
    """Execute decode flow from plugin context or standalone usage."""

    console = context.console if context is not None else Console()
    source = _resolve_input(text, file_path)
    source = _normalize_input(source)

    cache_token = hashlib.sha256(f"{source}|depth={int(max_depth)}".encode("utf-8", errors="ignore")).hexdigest()
    result: dict[str, Any]
    cached = load_json_cache(cache_key("smart_decode", cache_token))
    if isinstance(cached, dict) and "best" in cached and "candidates" in cached:
        result = cached
        result["cache_hit"] = True
    else:
        with console.status("[cyan]Decoding layers...[/cyan]", spinner="dots"):
            result = decode_recursive(source, max_depth=max_depth)
        save_json_cache(cache_key("smart_decode", cache_token), result)

    if result.get("cache_hit"):
        console.print("[cyan]smart-decode cache hit[/cyan]")

    _render_result(console, result)

    if context is not None:
        context.cache["smart_decode_result"] = result
        _save_workspace_output(result, context.cache)
        return 0
    return result


def _save_workspace_output(result: dict[str, Any], cache: dict[str, Any]) -> None:
    """Persist decode output in active workspace decoded/ directory."""

    out_dir = workspace_output_dir("decoded", cache)
    if out_dir is None:
        return

    out_file = out_dir / "smart_decode_latest.txt"
    lines = ["# Smart Decode", ""]
    for layer in result.get("layers", []):
        lines.append(
            f"Layer {layer.get('layer')}: {layer.get('method')} score={layer.get('score')}"
        )
    lines.extend(["", "Best Output:", str(result.get("best", "")), "", "Candidates:"])
    for item in result.get("candidates", []):
        lines.append(
            f"- {item.get('method')} score={item.get('score')} text={str(item.get('text', ''))[:120]}"
        )
    out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


class SmartDecodePlugin:
    """Plugin adapter for SYCTF dynamic module loading."""

    name = name
    description = description

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register CLI arguments for smart-decode plugin."""

        parser.add_argument("text", nargs="?", help="Encoded text input")
        parser.add_argument("--file", help="Read encoded text from file")
        parser.add_argument("--max-depth", type=int, default=MAX_DEPTH_DEFAULT, help="Max recursion depth")

    def run(self, args: argparse.Namespace, context: Any) -> int:
        """Run plugin execution and return process status code."""

        return int(
            run(
                args.text,
                context=context,
                file_path=args.file,
                max_depth=args.max_depth,
            )
        )


plugin = SmartDecodePlugin()

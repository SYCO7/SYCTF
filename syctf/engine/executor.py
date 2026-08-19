"""Executes one solve step and folds the result back into the context.

Only safe, in-process collectors run here -- no untrusted binaries. External
tools remain operator-driven via the recommended modules. That is a deliberate
safety boundary for unattended autonomous runs.
"""

from __future__ import annotations

import base64
import binascii
import codecs
from pathlib import Path

from syctf.engine.collectors import (
    classify_text,
    entropy_report,
    extract_strings,
    file_hashes,
    identify_file,
)
from syctf.engine.context import Observation, SolveContext
from syctf.engine.playbooks import detect_category
from syctf.flags.detector import FlagDetector


def _b64(data: bytes) -> bytes:
    return base64.b64decode(data + b"=" * (-len(data) % 4), validate=False)


def _b32(data: bytes) -> bytes:
    pad = (-len(data)) % 8
    return base64.b32decode(data.upper() + b"=" * pad)


_TRANSFORMS = {
    "base64": lambda d: _b64(d),
    "base32": lambda d: _b32(d),
    "hex": lambda d: binascii.unhexlify(d.strip().replace(b" ", b"")),
    "rot13": lambda d: codecs.encode(d.decode("ascii", "ignore"), "rot13").encode(),
    "reverse": lambda d: d[::-1],
    "bits": lambda d: bytes(int(b, 2) for b in d.split()),
}


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    return good / len(data)


class Executor:
    """Runs a single named step and returns an Observation."""

    def __init__(self, detector: FlagDetector | None = None) -> None:
        self.detector = detector or FlagDetector()

    def run(self, ctx: SolveContext, step: int, tool: str) -> Observation:
        handler = getattr(self, f"_do_{tool.replace('-', '_')}", None)
        if handler is None:
            return Observation(step=step, tool=tool, ok=False, summary="no such collector")
        try:
            summary, output = handler(ctx)
        except Exception as exc:  # collectors must never crash the loop
            return Observation(step=step, tool=tool, ok=False, summary=f"error: {exc}")
        flags = [h.value for h in self.detector.scan(output, source=tool) if not h.placeholder]
        return Observation(step=step, tool=tool, ok=True, summary=summary, output=output, flags=flags)

    # -- collectors ---------------------------------------------------------
    def _first_file(self, ctx: SolveContext) -> Path | None:
        return ctx.files[0] if ctx.files else None

    def _do_identify(self, ctx: SolveContext):
        path = self._first_file(ctx)
        if path is None:
            return ("no file to identify", "")
        summary, detail = identify_file(path)
        if ctx.category in ("unknown", ""):
            ctx.category = detect_category(kind=ctx.kind, file_type=summary, path=path)
        return (summary, detail)

    def _do_hashes(self, ctx: SolveContext):
        path = self._first_file(ctx)
        return file_hashes(path) if path else ("no file", "")

    def _do_entropy(self, ctx: SolveContext):
        path = self._first_file(ctx)
        return entropy_report(path) if path else ("no file", "")

    def _do_strings(self, ctx: SolveContext):
        outputs = []
        summary_bits = []
        for path in ctx.files[:5]:
            summary, output = extract_strings(path)
            summary_bits.append(f"{path.name}: {summary}")
            outputs.append(f"# {path.name}\n{output}")
        if not outputs:
            return ("no files", "")
        return ("; ".join(summary_bits), "\n".join(outputs))

    def _do_classify_text(self, ctx: SolveContext):
        text = ctx.target if ctx.kind == "text" else ""
        if not text:
            path = self._first_file(ctx)
            if path is not None:
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")[:5000]
                except OSError:
                    text = ""
        if not text:
            return ("no text", "")
        label, sample = classify_text(text)
        return (f"text looks {label}", sample)

    def _do_auto_decode(self, ctx: SolveContext):
        """Breadth-first decode search; stop early on a flag."""

        seed = ctx.target if ctx.kind == "text" else ""
        if not seed:
            path = self._first_file(ctx)
            if path is not None:
                try:
                    seed = path.read_text(encoding="utf-8", errors="ignore").strip()[:4000]
                except OSError:
                    seed = ""
        if not seed:
            return ("no input to decode", "")

        frontier: list[tuple[bytes, list[str]]] = [(seed.encode(), [])]
        best: tuple[float, str, list[str]] = (0.0, seed, [])
        for _depth in range(4):
            nxt: list[tuple[bytes, list[str]]] = []
            for data, chain in frontier:
                for name, fn in _TRANSFORMS.items():
                    try:
                        out = fn(data)
                    except (binascii.Error, ValueError, UnicodeDecodeError):
                        continue
                    if not out or out == data:
                        continue
                    ratio = _printable_ratio(out)
                    text = out.decode("ascii", "ignore")
                    hits = self.detector.scan(text)
                    real = [h for h in hits if not h.placeholder]
                    new_chain = chain + [name]
                    if real:
                        return (f"decoded via {' -> '.join(new_chain)}", text[:2000])
                    if ratio > best[0]:
                        best = (ratio, text, new_chain)
                    if ratio > 0.7:
                        nxt.append((out, new_chain))
            frontier = nxt[:8]
            if not frontier:
                break
        ratio, text, chain = best
        label = f"best chain {' -> '.join(chain)} (printable={ratio:.2f})" if chain else "no decode improved input"
        return (label, text[:2000])

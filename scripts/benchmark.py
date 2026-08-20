#!/usr/bin/env python3
"""Benchmark SYCTF's solve rate over a folder of challenges.

    python scripts/benchmark.py [folder] [flag_format] [--ai]

Defaults to the bundled examples/challenges with the deterministic engine (no
AI). Prints a per-challenge board + an overall solve rate you can quote.
"""

from __future__ import annotations

import sys
from pathlib import Path

from syctf.engine.arena import Arena


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--ai"]
    use_ai = "--ai" in sys.argv[1:]
    root = Path(args[0]) if args else Path(__file__).resolve().parents[1] / "examples" / "challenges"
    fmt = args[1] if len(args) > 1 else None

    if not root.is_dir():
        print(f"not a directory: {root}")
        return 2

    arena = Arena(use_ai=use_ai, flag_format=fmt)
    result = arena.run(root)

    width = max((len(e.name) for e in result.entries), default=10)
    for e in result.entries:
        mark = "PASS" if e.solved else "----"
        print(f"  [{mark}] {e.name:<{width}}  {e.category:<10}  {e.flag or ''}")

    rate = (result.solved / result.total * 100) if result.total else 0.0
    mode = "AI-assisted" if use_ai else "deterministic (no AI)"
    print(f"\nSYCTF solve rate ({mode}): {result.solved}/{result.total} = {rate:.0f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

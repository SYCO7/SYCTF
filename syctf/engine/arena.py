"""Arena mode — batch-solve a whole directory of challenges into a scoreboard.

Point it at a CTF folder; it runs the autonomous engine on each challenge
(subdirectory or loose file) and tallies which ones fell. Great for sweeping a
downloaded event before you dig in by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from syctf.engine import Engine


@dataclass(slots=True)
class ArenaEntry:
    name: str
    category: str
    solved: bool
    flag: str | None
    steps: int


@dataclass(slots=True)
class ArenaResult:
    entries: list[ArenaEntry] = field(default_factory=list)

    @property
    def solved(self) -> int:
        return sum(1 for e in self.entries if e.solved)

    @property
    def total(self) -> int:
        return len(self.entries)


def scan_targets(root: Path) -> list[Path]:
    """Each immediate child (dir or file) is treated as one challenge."""

    out: list[Path] = []
    for child in sorted(root.iterdir()):
        if child.name.startswith(".") or child.name in {"platform", "node_modules", "__pycache__"}:
            continue
        out.append(child)
    return out


class Arena:
    """Runs the solve engine across many challenges."""

    def __init__(self, *, use_ai: bool = False, flag_format: str | None = None, budget: int = 8) -> None:
        self.engine = Engine(use_ai=use_ai)
        self.use_ai = use_ai
        self.flag_format = flag_format
        self.budget = budget

    def run(self, root: Path, *, on_result=None) -> ArenaResult:
        result = ArenaResult()
        for target in scan_targets(root):
            try:
                solved = self.engine.solve(
                    str(target),
                    flag_format=self.flag_format,
                    use_ai=self.use_ai,
                    budget=self.budget,
                )
                entry = ArenaEntry(target.name, solved.category, solved.solved, solved.flag, solved.steps)
            except Exception:  # one bad challenge must not kill the sweep
                entry = ArenaEntry(target.name, "error", False, None, 0)
            result.entries.append(entry)
            if on_result is not None:
                on_result(entry)
        return result

"""Cross-challenge solve memory (sqlite).

SYCTF remembers how past challenges fell — category + winning technique — and
feeds that back as a hint on new challenges of the same kind, so it gets better
the more you use it. Never stores or leaks flags into hints (techniques only).
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from syctf.core.paths import get_cache_dir


@dataclass(slots=True)
class SolveRecord:
    name: str
    category: str
    technique: str
    flag: str
    ts: float


class SolveMemory:
    """Persistent record of solved challenges, keyed by category/technique."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (get_cache_dir() / "solves.db")
        self._init()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.path))

    def _init(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS solves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT, category TEXT, technique TEXT, flag TEXT, ts REAL
                )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cat ON solves(category)")

    def record(self, *, name: str, category: str, technique: str, flag: str) -> None:
        """Store one solved challenge (deduped by name+flag)."""

        with self._conn() as conn:
            exists = conn.execute(
                "SELECT 1 FROM solves WHERE name=? AND flag=? LIMIT 1", (name, flag)
            ).fetchone()
            if exists:
                return
            conn.execute(
                "INSERT INTO solves(name, category, technique, flag, ts) VALUES(?,?,?,?,?)",
                (name, category, technique, flag, time.time()),
            )

    def similar(self, category: str, limit: int = 8) -> list[SolveRecord]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT name, category, technique, flag, ts FROM solves "
                "WHERE category=? ORDER BY ts DESC LIMIT ?",
                (category, limit),
            ).fetchall()
        return [SolveRecord(*row) for row in rows]

    def hint(self, category: str) -> str:
        """A technique hint for this category (no flags) — fed to the AI prompt."""

        recs = self.similar(category)
        if not recs:
            return ""
        counts: dict[str, int] = {}
        for rec in recs:
            counts[rec.technique] = counts.get(rec.technique, 0) + 1
        top = sorted(counts, key=lambda t: counts[t], reverse=True)[:3]
        return f"Past {category} challenges here were solved with: {', '.join(top)}."

    def stats(self) -> dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM solves").fetchone()[0]
            by_cat = dict(conn.execute("SELECT category, COUNT(*) FROM solves GROUP BY category").fetchall())
            by_tech = dict(
                conn.execute(
                    "SELECT technique, COUNT(*) FROM solves GROUP BY technique ORDER BY 2 DESC LIMIT 10"
                ).fetchall()
            )
        return {"total": total, "by_category": by_cat, "by_technique": by_tech}

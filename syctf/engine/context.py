"""Shared state for one autonomous solve run."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class Observation:
    """One tool/collector result folded back into the solve state."""

    step: int
    tool: str
    ok: bool
    summary: str
    output: str = ""
    flags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SolveContext:
    """Everything known about a challenge as the engine works it."""

    target: str
    kind: str = "unknown"          # file | dir | text | url | host | unknown
    category: str = "unknown"      # crypto | rev | pwn | web | forensics | osint | misc
    flag_format: str | None = None
    files: list[Path] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    transcript: list[str] = field(default_factory=list)
    tried_tools: set[str] = field(default_factory=set)
    flag: str | None = None
    budget: int = 12

    @property
    def steps_used(self) -> int:
        return len(self.observations)

    @property
    def solved(self) -> bool:
        return self.flag is not None

    def add_observation(self, obs: Observation) -> None:
        self.observations.append(obs)
        self.tried_tools.add(obs.tool)

    def note(self, text: str) -> None:
        self.findings.append(text)

    def log(self, text: str) -> None:
        self.transcript.append(text)

    def evidence_corpus(self, limit: int = 20000) -> str:
        """Concatenated tool output -- the ground truth for verification."""

        chunks = [o.output for o in self.observations if o.output]
        joined = "\n".join(chunks)
        return joined[-limit:] if len(joined) > limit else joined

    def state_digest(self, limit: int = 4000) -> str:
        """Compact summary of progress for LLM prompting."""

        lines = [f"target={self.target!r} kind={self.kind} category={self.category}"]
        if self.flag_format:
            lines.append(f"flag_format={self.flag_format}")
        if self.files:
            lines.append("files: " + ", ".join(p.name for p in self.files[:10]))
        for obs in self.observations[-8:]:
            status = "ok" if obs.ok else "fail"
            lines.append(f"[{obs.step}] {obs.tool} ({status}): {obs.summary}")
        if self.findings:
            lines.append("findings: " + " | ".join(self.findings[-6:]))
        digest = "\n".join(lines)
        return digest[:limit]

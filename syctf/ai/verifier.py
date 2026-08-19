"""Anti-hallucination layer for SYCTF AI output.

CTF answers are checkable, so we never trust the model's word alone. Four
independent guards, cheapest first:

1. **Flag grounding** -- a claimed flag is trusted only if it is not a template
   AND it literally appears in real tool/file evidence. Invented flags are
   rejected and logged.
2. **Self-consistency** -- sample the model N times; agreement is the
   confidence signal. Wide disagreement => abstain instead of asserting.
3. **Claim grounding** -- factual claims must be supported by evidence text.
4. **Learning memory** -- every caught hallucination is written to a jsonl the
   engine feeds back as negative few-shot examples, so the same mistake gets
   pressured out on later runs.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field

from syctf.ai.providers import ChatResult
from syctf.core.paths import get_cache_dir
from syctf.flags.detector import FlagDetector, FlagHit

_WS = re.compile(r"\s+")


def _normalize(text: str) -> str:
    return _WS.sub(" ", (text or "").strip().lower())


@dataclass(slots=True)
class ConsistencyReport:
    """Outcome of self-consistency voting over N samples."""

    answer: str
    agreement: float          # fraction of samples that agreed with the winner
    samples: int
    distinct: int

    @property
    def confident(self) -> bool:
        return self.samples >= 2 and self.agreement >= 0.6


@dataclass(slots=True)
class FlagVerdict:
    """Which claimed flags survived grounding + decoy screening."""

    trusted: list[str] = field(default_factory=list)
    unverified: list[str] = field(default_factory=list)
    decoys: list[str] = field(default_factory=list)
    reason: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.trusted)


class HallucinationMemory:
    """Append-only jsonl log of caught hallucinations for learning."""

    def __init__(self, path=None) -> None:
        self.path = path or (get_cache_dir() / "hallucinations.jsonl")

    def record(self, kind: str, claim: str, note: str = "") -> None:
        entry = {"kind": kind, "claim": claim[:500], "note": note[:300]}
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def recent(self, n: int = 10) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out: list[dict] = []
        for line in lines[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def as_few_shot(self, n: int = 5) -> str:
        """Render recent misses as a negative-example block for prompts."""

        rows = self.recent(n)
        if not rows:
            return ""
        bullets = "\n".join(f"- ({r.get('kind')}) do NOT claim: {r.get('claim')}" for r in rows)
        return "Previously caught mistakes to avoid repeating:\n" + bullets


class Verifier:
    """Bundles the guards behind one object the engine can call."""

    def __init__(self, detector: FlagDetector | None = None, memory: HallucinationMemory | None = None) -> None:
        self.detector = detector or FlagDetector()
        self.memory = memory or HallucinationMemory()

    # -- guard 1: flag grounding -------------------------------------------
    def flag_guard(self, model_text: str, evidence: str) -> FlagVerdict:
        """Trust a claimed flag only if it is real and appears in evidence."""

        verdict = FlagVerdict()
        evidence_norm = _normalize(evidence)
        hits: list[FlagHit] = self.detector.scan(model_text, source="model")
        for hit in hits:
            if hit.placeholder:
                verdict.unverified.append(hit.value)
                self.memory.record("placeholder_flag", hit.value, "looks templated")
                continue
            if hit.decoy:
                # A real-looking but planted decoy: never report it as the answer.
                verdict.decoys.append(hit.value)
                self.memory.record("decoy_flag", hit.value, "matches a known decoy marker")
                continue
            if _normalize(hit.value) in evidence_norm:
                verdict.trusted.append(hit.value)
            else:
                verdict.unverified.append(hit.value)
                self.memory.record("ungrounded_flag", hit.value, "not present in tool/file evidence")
        if verdict.trusted:
            verdict.reason = "grounded in evidence"
        elif verdict.decoys:
            verdict.reason = "only decoy flag(s) found -- keep looking"
        elif verdict.unverified:
            verdict.reason = "flag(s) not grounded -- treat as unverified"
        else:
            verdict.reason = "no flag detected"
        return verdict

    def verify_flag(
        self,
        flag: str,
        *,
        expected_sha256: str | None = None,
        expected_md5: str | None = None,
        checker=None,
    ) -> bool:
        """Definitively confirm a flag against an oracle.

        The only way to be *certain* a flag is real (not a decoy) is to check it
        against something authoritative: a hash the challenge published, or a
        checker/submit callback. With no oracle, returns False (cannot prove).
        """

        import hashlib

        value = flag.strip()
        if expected_sha256:
            return hashlib.sha256(value.encode()).hexdigest().lower() == expected_sha256.strip().lower()
        if expected_md5:
            return hashlib.md5(value.encode()).hexdigest().lower() == expected_md5.strip().lower()
        if callable(checker):
            try:
                return bool(checker(value))
            except Exception:  # noqa: BLE001
                return False
        return False

    # -- guard 2: self-consistency -----------------------------------------
    def self_consistency(self, results: list[ChatResult]) -> ConsistencyReport:
        """Vote across samples; prefer an agreed extracted flag, else text."""

        texts = [r.text for r in results if r and r.text.strip()]
        if not texts:
            return ConsistencyReport(answer="", agreement=0.0, samples=0, distinct=0)

        keys: list[str] = []
        display: dict[str, str] = {}
        for text in texts:
            flags = self.detector.scan(text)
            best = self.detector.best(flags)
            key = _normalize(best.value) if best else _normalize(text)[:200]
            keys.append(key)
            display.setdefault(key, best.value if best else text.strip())

        counts = Counter(keys)
        winner, votes = counts.most_common(1)[0]
        return ConsistencyReport(
            answer=display[winner],
            agreement=votes / len(keys),
            samples=len(keys),
            distinct=len(counts),
        )

    # -- guard 3: claim grounding ------------------------------------------
    def grounded(self, claim: str, evidence: str, *, min_overlap: float = 0.5) -> bool:
        """Heuristic: enough of the claim's tokens appear in the evidence."""

        claim_tokens = {t for t in re.findall(r"[a-z0-9_]{3,}", _normalize(claim))}
        if not claim_tokens:
            return False
        evidence_tokens = set(re.findall(r"[a-z0-9_]{3,}", _normalize(evidence)))
        overlap = len(claim_tokens & evidence_tokens) / len(claim_tokens)
        return overlap >= min_overlap

    # -- guard 4: gate ------------------------------------------------------
    def gate(self, report: ConsistencyReport, *, threshold: float = 0.6) -> bool:
        """Return True when the answer is confident enough to assert."""

        return report.samples >= 2 and report.agreement >= threshold

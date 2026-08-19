"""The autonomous solve loop: observe -> decide -> act -> verify."""

from __future__ import annotations

from dataclasses import dataclass, field

from syctf.engine.context import SolveContext
from syctf.engine.executor import Executor
from syctf.engine.planner import Planner
from syctf.engine.playbooks import RECOMMENDED_MODULES
from syctf.flags.detector import FlagDetector

_REASON_SYSTEM = (
    "You are SYCTF's solver brain: a senior CTF player. You are given only the "
    "real evidence collected from the challenge. Reason step by step about the "
    "most likely path to the flag. If the evidence already contains the flag, "
    "state it verbatim. NEVER fabricate a flag: if you are not certain, say "
    "'no flag yet' and name the single next action. Ground every claim in the "
    "evidence shown."
)


@dataclass(slots=True)
class SolveResult:
    """Final outcome of an autonomous run."""

    solved: bool
    flag: str | None
    category: str
    steps: int
    transcript: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    recommended_modules: list[str] = field(default_factory=list)
    ai_summary: str = ""
    confidence: float = 0.0
    used_ai: bool = False


class Reasoner:
    """Drives a SolveContext to a (verified) flag or a next-step report."""

    def __init__(self, router=None, verifier=None, detector: FlagDetector | None = None) -> None:
        self.detector = detector or FlagDetector()
        self.executor = Executor(detector=self.detector)
        self.planner = Planner(router=router)
        self.router = router
        self.verifier = verifier

    def _record_flag(self, ctx: SolveContext, value: str, source: str) -> None:
        ctx.flag = value
        ctx.note(f"FLAG via {source}: {value}")
        ctx.log(f"[flag] {value} (source={source})")

    def solve(self, ctx: SolveContext, *, use_ai: bool = True, ensemble: int = 1) -> SolveResult:
        # 1) Deterministic, grounded pass -- always runs, no tokens spent.
        plan = self.planner.initial_plan(ctx)
        step = 0
        while step < ctx.budget and not ctx.solved:
            tool = plan.pop(0) if plan else self.planner.llm_next(ctx)
            if tool is None:
                break
            if tool in ctx.tried_tools:
                continue
            step += 1
            obs = self.executor.run(ctx, step, tool)
            ctx.add_observation(obs)
            ctx.log(f"[{step}] {tool}: {obs.summary}")
            if obs.flags:
                # Flags here come straight from real bytes -> grounded/trusted.
                best = self.detector.best(self.detector.scan("\n".join(obs.flags)))
                if best:
                    self._record_flag(ctx, best.value, f"collector:{tool}")

        # 2) AI reasoning pass over the collected evidence (verified).
        used_ai = False
        ai_summary = ""
        confidence = 0.0
        if use_ai and self.router is not None and not ctx.solved:
            used_ai = True
            ai_summary, confidence = self._ai_pass(ctx, ensemble=ensemble)

        return SolveResult(
            solved=ctx.solved,
            flag=ctx.flag,
            category=ctx.category,
            steps=ctx.steps_used,
            transcript=list(ctx.transcript),
            findings=list(ctx.findings),
            recommended_modules=RECOMMENDED_MODULES.get(ctx.category, RECOMMENDED_MODULES["unknown"]),
            ai_summary=ai_summary,
            confidence=confidence,
            used_ai=used_ai,
        )

    def _ai_pass(self, ctx: SolveContext, *, ensemble: int) -> tuple[str, float]:
        evidence = ctx.evidence_corpus()
        negatives = ""
        if self.verifier is not None:
            negatives = self.verifier.memory.as_few_shot()
        prompt = (
            f"{negatives}\n\nChallenge state:\n{ctx.state_digest()}\n\n"
            f"Collected evidence (verbatim, this is the ONLY ground truth):\n{evidence[:8000]}\n\n"
            "Give: (1) most likely category & why, (2) the single best next action, "
            "(3) the flag ONLY if it appears in the evidence above."
        ).strip()
        messages = [
            {"role": "system", "content": _REASON_SYSTEM},
            {"role": "user", "content": prompt},
        ]

        confidence = 0.0
        if self.verifier is not None and ensemble > 1:
            samples = self.router.ensemble(messages, tier="reason", n=ensemble)
            report = self.verifier.self_consistency(samples)
            summary = report.answer
            confidence = report.agreement
            text_for_flags = "\n".join(s.text for s in samples)
        else:
            route = self.router.complete(messages, tier="reason")
            summary = route.result.text
            confidence = 0.5
            text_for_flags = summary

        # Anti-hallucination: only accept an AI flag grounded in real evidence.
        if self.verifier is not None:
            verdict = self.verifier.flag_guard(text_for_flags, evidence)
            if verdict.trusted:
                best = self.detector.best(self.detector.scan("\n".join(verdict.trusted)))
                if best:
                    self._record_flag(ctx, best.value, "ai+grounded")
                    confidence = max(confidence, 0.9)
            elif verdict.unverified:
                ctx.log(f"[guard] rejected ungrounded AI flag(s): {verdict.unverified}")
        return summary, confidence

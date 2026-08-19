"""Chooses the next step: deterministic playbook first, LLM second."""

from __future__ import annotations

import re

from syctf.engine.context import SolveContext
from syctf.engine.playbooks import playbook_for

ALL_TOOLS = ["identify", "hashes", "entropy", "strings", "classify-text", "auto-decode"]

_NEXT_SYSTEM = (
    "You are the planner for an autonomous CTF solver. "
    "Pick the single most useful NEXT tool from the allowed list, or reply STOP. "
    "Reply with ONLY the tool name or STOP -- no prose, no explanation. "
    "Never invent tools or flags."
)


class Planner:
    """Produces an ordered plan and, when it runs dry, asks the model."""

    def __init__(self, router=None) -> None:
        self.router = router

    def initial_plan(self, ctx: SolveContext) -> list[str]:
        """Deterministic step list for the detected category."""

        return [t for t in playbook_for(ctx.category) if t in ALL_TOOLS]

    def llm_next(self, ctx: SolveContext) -> str | None:
        """Ask the model for one more tool, constrained to the allowed set."""

        if self.router is None:
            return None
        untried = [t for t in ALL_TOOLS if t not in ctx.tried_tools]
        if not untried:
            return None
        prompt = (
            f"State:\n{ctx.state_digest()}\n\n"
            f"Allowed tools (not yet tried): {', '.join(untried)}\n"
            "Answer with one tool name from that list, or STOP."
        )
        try:
            reply = self.router.complete_text(prompt, system=_NEXT_SYSTEM, tier="route")
        except Exception:
            return None
        token = re.split(r"\s+", reply.strip().lower())[0] if reply.strip() else "stop"
        if token == "stop":
            return None
        # Guard against hallucinated tool names.
        return token if token in untried else None

"""Autonomous agent tests using a scripted fake router (no real LLM)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from rich.console import Console

from syctf.core.plugin_loader import PluginLoader
from syctf.core.types import AppConfig, ExecutionContext
from syctf.engine.agent import AgentOrchestrator
from syctf.ai.verifier import Verifier

MODULES_ROOT = Path(__file__).resolve().parents[2] / "syctf" / "modules"


class FakeRouter:
    """Returns scripted JSON actions in order."""

    def __init__(self, actions: list[dict]):
        self._replies = [json.dumps(a) for a in actions]
        self.calls = 0

    def complete_text(self, prompt, *, system=None, tier="reason"):
        reply = self._replies[min(self.calls, len(self._replies) - 1)]
        self.calls += 1
        return reply


def _orchestrator(actions):
    loader = PluginLoader(modules_roots=[MODULES_ROOT], logger=logging.getLogger("t"))
    ctx = ExecutionContext(
        config=AppConfig(),
        logger=logging.getLogger("t"),
        console=Console(),
        plugin_loader=loader,
        cache={},
    )
    return AgentOrchestrator(loader, ctx, FakeRouter(actions), verifier=Verifier(), console=Console())


def test_catalog_lists_real_modules():
    agent = _orchestrator([{"done": False}])
    catalog = agent._catalog()
    assert "crypto/xor-tools" in catalog
    assert "web/jwt-tool" in catalog


def test_agent_runs_real_module_to_flag():
    pt = b"flag{agent_pwned}"
    ct = bytes(b ^ 0x13 for b in pt).hex()
    agent = _orchestrator([{"tool": "crypto/xor-tools", "args": {"data": ct, "raw": False}, "rationale": "xor"}])
    result = agent.run("dummy", budget=3)
    assert result.solved
    assert result.flag == "flag{agent_pwned}"
    assert result.calls and result.calls[0].tool == "crypto/xor-tools"


def test_agent_rejects_ungrounded_done_then_solves():
    pt = b"flag{grounded_only}"
    ct = bytes(b ^ 0x22 for b in pt).hex()
    actions = [
        {"done": True, "flag": "flag{hallucinated}"},                      # no evidence -> rejected
        {"tool": "crypto/xor-tools", "args": {"data": ct, "raw": False}},  # real solve
    ]
    agent = _orchestrator(actions)
    result = agent.run("dummy", budget=4)
    assert result.solved
    assert result.flag == "flag{grounded_only}"


def test_agent_handles_unknown_tool():
    agent = _orchestrator([{"tool": "does/not-exist", "args": {}}])
    result = agent.run("dummy", budget=1)
    assert not result.solved
    assert result.calls[0].ok is False

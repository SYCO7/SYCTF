"""Autonomous tool-using agent: the LLM drives real SYCTF modules to a flag.

Unlike the deterministic ``Engine`` (safe in-process collectors only), the agent
plans with the model and executes actual menu modules — rsa-attacks, rop-finder,
jwt-tool, sqli-probe, osint, mobile, cloud, … — feeding each tool's real output
back as grounded evidence. Anti-hallucination gates every claimed flag.

This is opt-in (``syctf agent``) because it can run network/tools unattended.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

from syctf.flags.detector import FlagDetector

_SYSTEM = (
    "You are SYCTF-Agent, an autonomous CTF solver with 10 years of experience. "
    "You are given a GOAL, a TARGET, a TOOL CATALOG, and the transcript so far. "
    "Choose ONE tool to run next, or finish. Respond with ONLY a single JSON object:\n"
    '  {"tool": "category/module", "args": {"argname": "value"}, "rationale": "why"}\n'
    "or, when the flag is present in the evidence:\n"
    '  {"done": true, "flag": "the_exact_flag_from_evidence"}\n'
    "Rules: use only tools from the catalog; never invent a flag — it must appear "
    "verbatim in prior tool output; prefer the cheapest tool that advances the goal; "
    "do not repeat a tool call that already failed the same way."
)


@dataclass(slots=True)
class ToolCall:
    tool: str
    args: dict[str, Any]
    ok: bool
    output: str
    rationale: str = ""


@dataclass(slots=True)
class AgentResult:
    solved: bool
    flag: str | None
    steps: int
    transcript: list[str] = field(default_factory=list)
    calls: list[ToolCall] = field(default_factory=list)


class AgentOrchestrator:
    """Runs the plan→act→observe→verify loop over real modules."""

    def __init__(self, loader, context, router, verifier=None, console: Console | None = None) -> None:
        self.loader = loader
        self.context = context
        self.router = router
        self.verifier = verifier
        self.console = console or Console()
        self.detector = FlagDetector()
        self._registry = self._build_registry()

    # -- tool registry ------------------------------------------------------
    def _categories(self) -> list[str]:
        cats: set[str] = set()
        for root in getattr(self.loader, "modules_roots", []):
            from pathlib import Path

            p = Path(root)
            if p.is_dir():
                cats.update(c.name for c in p.iterdir() if c.is_dir() and not c.name.startswith("__"))
        return sorted(cats)

    def _build_registry(self) -> dict[str, Any]:
        registry: dict[str, Any] = {}
        for category in self._categories():
            for plugin in self.loader.discover(category).values():
                registry[f"{category}/{plugin.name}"] = plugin
        return registry

    def _catalog(self) -> str:
        lines: list[str] = []
        for key, plugin in sorted(self._registry.items()):
            parser = argparse.ArgumentParser(add_help=False)
            try:
                plugin.add_arguments(parser)
            except Exception:  # noqa: BLE001
                pass
            opts = []
            for action in parser._actions:  # noqa: SLF001
                if action.dest in ("help", "_help"):
                    continue
                flag = action.option_strings[0] if action.option_strings else action.dest
                req = "*" if getattr(action, "required", False) else ""
                opts.append(f"{flag}{req}")
            lines.append(f"- {key} :: {getattr(plugin, 'description', '')} :: args={', '.join(opts) or 'none'}")
        return "\n".join(lines)

    # -- module execution ---------------------------------------------------
    def _invoke(self, key: str, args: dict[str, Any]) -> ToolCall:
        plugin = self._registry.get(key)
        if plugin is None:
            return ToolCall(tool=key, args=args, ok=False, output=f"unknown tool: {key}")

        parser = argparse.ArgumentParser(add_help=False)
        plugin.add_arguments(parser)
        norm = {str(k).lstrip("-").replace("-", "_"): v for k, v in (args or {}).items()}

        positionals: list[str] = []
        options: list[str] = []
        for action in parser._actions:  # noqa: SLF001
            if action.dest in ("help", "_help") or action.dest not in norm:
                continue
            value = norm[action.dest]
            if action.option_strings:
                if action.nargs == 0 or isinstance(value, bool):
                    if value:
                        options.append(action.option_strings[0])
                else:
                    options += [action.option_strings[0], str(value)]
            else:
                positionals.append(str(value))

        rec = Console(record=True, width=100)
        # Capture module output by temporarily swapping the shared context's
        # console; cache/state stay shared so flags propagate.
        original_console = self.context.console
        self.context.console = rec
        try:
            ns = parser.parse_args(positionals + options)
            plugin.run(ns, self.context)
            ok = True
        except SystemExit:
            return ToolCall(tool=key, args=args, ok=False, output="argument error: " + rec.export_text())
        except Exception as exc:  # noqa: BLE001
            return ToolCall(tool=key, args=args, ok=False, output=f"tool error: {exc}\n" + rec.export_text())
        finally:
            self.context.console = original_console
        return ToolCall(tool=key, args=args, ok=ok, output=rec.export_text())

    # -- planning -----------------------------------------------------------
    def _decide(self, goal: str, target: str, transcript: list[str]) -> dict[str, Any] | None:
        prompt = (
            f"GOAL: {goal}\nTARGET: {target}\n\nTOOL CATALOG:\n{self._catalog()}\n\n"
            f"TRANSCRIPT (most recent last):\n" + "\n".join(transcript[-12:]) +
            "\n\nRespond with ONE JSON action now."
        )
        try:
            reply = self.router.complete_text(prompt, system=_SYSTEM, tier="reason")
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[red]planner error: {exc}[/red]")
            return None
        match = re.search(r"\{.*\}", reply, re.DOTALL)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

    # -- main loop ----------------------------------------------------------
    def run(self, target: str, *, goal: str = "capture the flag", budget: int = 10) -> AgentResult:
        transcript: list[str] = [f"target set to {target}"]
        calls: list[ToolCall] = []
        evidence: list[str] = []
        self.context.cache["target"] = target

        for step in range(1, budget + 1):
            action = self._decide(goal, target, transcript)
            if action is None:
                transcript.append("planner produced no valid action; stopping")
                break

            if action.get("done"):
                claim = str(action.get("flag", ""))
                corpus = "\n".join(evidence)
                if self.verifier is not None:
                    verdict = self.verifier.flag_guard(claim, corpus)
                    if verdict.trusted:
                        return AgentResult(True, verdict.trusted[0], step - 1, transcript, calls)
                    transcript.append(f"[guard] rejected ungrounded flag claim: {claim!r}")
                    continue
                if claim and claim in corpus:
                    return AgentResult(True, claim, step - 1, transcript, calls)
                transcript.append(f"[guard] flag claim not in evidence: {claim!r}")
                continue

            tool = str(action.get("tool", ""))
            args = action.get("args", {}) or {}
            self.console.print(f"[cyan][{step}][/cyan] {tool} {args}  [dim]{action.get('rationale','')[:80]}[/dim]")
            call = self._invoke(tool, args)
            calls.append(call)
            evidence.append(call.output)
            status = "ok" if call.ok else "FAIL"
            transcript.append(f"[{step}] ran {tool} ({status}); output: {call.output[:600]}")

            # grounded flag from real tool output (skip templates and decoys)
            for hit in self.detector.scan(call.output):
                if hit.real:
                    return AgentResult(True, hit.value, step, transcript, calls)
            decoys = self.detector.decoys(self.detector.scan(call.output))
            if decoys:
                transcript.append(f"[decoy] ignored planted decoy(s): {[d.value for d in decoys]}")
            if self.context.cache.get("flag"):
                return AgentResult(True, str(self.context.cache["flag"]), step, transcript, calls)

        return AgentResult(False, None, len(calls), transcript, calls)

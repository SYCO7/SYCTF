"""Anti-hallucination verifier tests."""

from __future__ import annotations

from syctf.ai.providers.base import ChatResult
from syctf.ai.verifier import HallucinationMemory, Verifier


def _mk(text: str) -> ChatResult:
    return ChatResult(text=text, provider="test", model="t")


def test_flag_guard_rejects_ungrounded(tmp_path):
    v = Verifier(memory=HallucinationMemory(path=tmp_path / "h.jsonl"))
    verdict = v.flag_guard("the flag is flag{invented}", evidence="nothing useful here")
    assert verdict.trusted == []
    assert "flag{invented}" in verdict.unverified
    assert not verdict.ok


def test_flag_guard_accepts_grounded(tmp_path):
    v = Verifier(memory=HallucinationMemory(path=tmp_path / "h.jsonl"))
    verdict = v.flag_guard("answer: flag{grounded}", evidence="strings: ... flag{grounded} ...")
    assert verdict.trusted == ["flag{grounded}"]
    assert verdict.ok


def test_flag_guard_rejects_placeholder(tmp_path):
    v = Verifier(memory=HallucinationMemory(path=tmp_path / "h.jsonl"))
    verdict = v.flag_guard("flag{your_flag_here}", evidence="flag{your_flag_here}")
    assert verdict.trusted == []


def test_self_consistency_majority(tmp_path):
    v = Verifier(memory=HallucinationMemory(path=tmp_path / "h.jsonl"))
    samples = [_mk("flag{win}"), _mk("the flag is flag{win}"), _mk("flag{other}")]
    report = v.self_consistency(samples)
    assert report.answer == "flag{win}"
    assert report.agreement >= 0.6
    assert report.confident


def test_memory_records_and_few_shot(tmp_path):
    mem = HallucinationMemory(path=tmp_path / "h.jsonl")
    mem.record("ungrounded_flag", "flag{bad}", "test")
    assert mem.recent(5)
    assert "do NOT claim" in mem.as_few_shot()

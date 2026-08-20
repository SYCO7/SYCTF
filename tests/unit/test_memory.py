"""Cross-challenge solve memory tests."""

from __future__ import annotations

from syctf.memory import SolveMemory


def test_record_dedup_and_stats(tmp_path):
    mem = SolveMemory(path=tmp_path / "m.db")
    mem.record(name="a", category="crypto", technique="xor", flag="flag{a}")
    mem.record(name="a", category="crypto", technique="xor", flag="flag{a}")   # dup ignored
    mem.record(name="b", category="crypto", technique="rsa", flag="flag{b}")
    mem.record(name="c", category="forensics", technique="stego", flag="flag{c}")
    stats = mem.stats()
    assert stats["total"] == 3
    assert stats["by_category"]["crypto"] == 2
    assert stats["by_category"]["forensics"] == 1


def test_similar_and_hint(tmp_path):
    mem = SolveMemory(path=tmp_path / "m.db")
    for i in range(3):
        mem.record(name=f"x{i}", category="crypto", technique="xor", flag=f"flag{{{i}}}")
    mem.record(name="r", category="crypto", technique="rsa", flag="flag{r}")
    sims = mem.similar("crypto")
    assert len(sims) == 4
    hint = mem.hint("crypto")
    assert "crypto" in hint and "xor" in hint          # most-used technique surfaces
    assert mem.hint("pwn") == ""                        # nothing learned yet


def test_hint_never_leaks_flags(tmp_path):
    mem = SolveMemory(path=tmp_path / "m.db")
    mem.record(name="a", category="web", technique="sqli", flag="flag{secret_value}")
    assert "secret_value" not in mem.hint("web")        # techniques only, never flags

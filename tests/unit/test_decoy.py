"""Fake / decoy flag handling — never report a planted decoy, never guess."""

from __future__ import annotations

import hashlib

from syctf.ai.verifier import Verifier
from syctf.flags import FlagDetector, is_decoy


def test_is_decoy_markers():
    assert is_decoy("flag{fake_flag}")
    assert is_decoy("flag{try_harder}")
    assert is_decoy("CTF{not_the_real_one}")
    assert not is_decoy("flag{r3al_pwn_2024}")


def test_best_skips_decoy_picks_real():
    d = FlagDetector()
    hits = d.scan("flag{decoy_nice_try} and flag{the_actual_win}")
    best = d.best(hits)
    assert best is not None and best.value == "flag{the_actual_win}"


def test_best_none_when_only_decoys():
    d = FlagDetector()
    hits = d.scan("flag{fake} flag{troll} flag{keep_looking}")
    assert d.best(hits) is None            # never returns a decoy as the answer
    assert len(d.decoys(hits)) == 3


def test_verifier_routes_decoys_not_trusted(tmp_path):
    from syctf.ai.verifier import HallucinationMemory

    v = Verifier(memory=HallucinationMemory(path=tmp_path / "h.jsonl"))
    # decoy is present in the evidence (grounded) but must still be rejected.
    verdict = v.flag_guard("the flag is flag{fake_decoy}", evidence="strings: flag{fake_decoy}")
    assert verdict.trusted == []
    assert "flag{fake_decoy}" in verdict.decoys
    assert "decoy" in verdict.reason


def test_verifier_verify_flag_oracle():
    v = Verifier()
    real = "flag{proven_by_hash}"
    digest = hashlib.sha256(real.encode()).hexdigest()
    assert v.verify_flag(real, expected_sha256=digest) is True
    assert v.verify_flag("flag{wrong}", expected_sha256=digest) is False
    assert v.verify_flag(real, checker=lambda f: f.endswith("hash}")) is True
    assert v.verify_flag(real) is False    # no oracle -> cannot positively prove

"""Flag detector tests."""

from __future__ import annotations

from syctf.flags import FlagDetector


def test_detects_common_wrappers():
    d = FlagDetector()
    vals = [h.value for h in d.scan("x flag{abc_123} y CTF{def} z")]
    assert "flag{abc_123}" in vals
    assert "CTF{def}" in vals


def test_marks_placeholder_flags():
    d = FlagDetector()
    hits = {h.value: h.placeholder for h in d.scan("flag{your_flag_here} flag{real_value}")}
    assert hits["flag{your_flag_here}"] is True
    assert hits["flag{real_value}"] is False


def test_custom_format_prefix():
    d = FlagDetector(custom_format="picoCTF{}")
    vals = [h.value for h in d.scan("picoCTF{custom_1}")]
    assert "picoCTF{custom_1}" in vals


def test_scan_bytes_extracts_printable():
    d = FlagDetector()
    blob = b"\x00\x01flag{from_bytes}\xff\xfe"
    vals = [h.value for h in d.scan_bytes(blob)]
    assert "flag{from_bytes}" in vals


def test_best_prefers_real_over_placeholder():
    d = FlagDetector()
    hits = d.scan("flag{example_xxxx} flag{genuine_win}")
    best = d.best(hits)
    assert best is not None and best.value == "flag{genuine_win}"

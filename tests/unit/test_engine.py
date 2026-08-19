"""Autonomous engine tests (deterministic, no AI backend)."""

from __future__ import annotations

import base64

from syctf.engine import Engine


def test_ingest_text_vs_host_vs_url():
    e = Engine(use_ai=False)
    assert e.ingest("aGVsbG8gd29ybGQ=").kind == "text"          # base64 is text, not host
    assert e.ingest("example.com").kind == "host"
    assert e.ingest("10.0.0.1:1337").kind == "host"
    assert e.ingest("https://ctf.example/chal").kind == "url"


def test_solve_base64_text_finds_flag():
    seed = base64.b64encode(b"flag{engine_ok}").decode()
    result = Engine(use_ai=False).solve(seed, use_ai=False)
    assert result.solved
    assert result.flag == "flag{engine_ok}"
    assert result.category == "crypto"


def test_solve_multilayer_chain():
    inner = base64.b64encode(b"flag{layered}").decode().encode()
    seed = base64.b64encode(inner).decode()  # base64(base64(flag))
    result = Engine(use_ai=False).solve(seed, use_ai=False)
    assert result.solved and result.flag == "flag{layered}"


def test_solve_file_with_embedded_flag(tmp_path):
    f = tmp_path / "chal.bin"
    f.write_bytes(b"\x00garbage----CTF{in_the_binary}----more\x01")
    result = Engine(use_ai=False).solve(str(f), use_ai=False)
    assert result.solved and result.flag == "CTF{in_the_binary}"


def test_no_flag_reports_recommended_modules(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"\x00\x01\x02\x03 nothing here \x04\x05")
    result = Engine(use_ai=False).solve(str(f), use_ai=False)
    assert not result.solved
    assert result.recommended_modules  # points operator at next tools


def test_custom_flag_format(tmp_path):
    f = tmp_path / "c.txt"
    f.write_text("noise picoCTF{custom_fmt} noise")
    result = Engine(use_ai=False).solve(str(f), flag_format="picoCTF{}", use_ai=False)
    assert result.solved and result.flag == "picoCTF{custom_fmt}"

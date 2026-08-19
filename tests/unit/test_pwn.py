"""Pwn analyzer tests: format-string builder (printf-simulated) + rop finder."""

from __future__ import annotations

import argparse
import logging
import re
import struct
import sys

from rich.console import Console

from syctf.core.types import AppConfig, ExecutionContext
from syctf.modules.pwn.fmtstr import build_probe_payload, build_write_payload


def _ctx() -> ExecutionContext:
    return ExecutionContext(
        config=AppConfig(),
        logger=logging.getLogger("test.pwn"),
        console=Console(),
        plugin_loader=None,
        cache={},
    )


def _simulate_printf(payload: bytes, offset: int, word: int) -> dict[int, int]:
    """Emulate printf on the payload; return the memory writes it performs."""

    # The address block = one word per %N$hhn directive, appended at the end.
    n_writes = len(re.findall(rb"%\d+\$hhn", payload))
    addr_len = n_writes * word
    fmt = payload[:-addr_len] if addr_len else payload
    tail = payload[-addr_len:] if addr_len else b""
    addr_args: dict[int, int] = {}
    first_arg = offset + len(fmt) // word
    for i in range(len(tail) // word):
        chunk = tail[i * word:(i + 1) * word]
        addr_args[first_arg + i] = struct.unpack("<I" if word == 4 else "<Q", chunk)[0]

    mem: dict[int, int] = {}
    counter = 0
    i = 0
    text = fmt
    token = re.compile(rb"%(\d+)c|%(\d+)\$hhn")
    pos = 0
    while pos < len(text):
        m = token.match(text, pos)
        if not m:
            counter += 1  # literal byte printed
            pos += 1
            continue
        if m.group(1) is not None:
            counter += int(m.group(1))
        else:
            arg = int(m.group(2))
            mem[addr_args[arg]] = counter & 0xFF
        pos = m.end()
    return mem


def test_fmt_write_single_byte_value_64():
    payload = build_write_payload(offset=6, writes=[(0x601050, 0xDE)], word=8, nbytes=1)
    mem = _simulate_printf(payload, offset=6, word=8)
    assert mem.get(0x601050) == 0xDE


def test_fmt_write_full_word_32():
    payload = build_write_payload(offset=4, writes=[(0x0804A000, 0x41424344)], word=4)
    mem = _simulate_printf(payload, offset=4, word=4)
    assert mem.get(0x0804A000) == 0x44
    assert mem.get(0x0804A001) == 0x43
    assert mem.get(0x0804A002) == 0x42
    assert mem.get(0x0804A003) == 0x41


def test_probe_payload_shape():
    p = build_probe_payload(5)
    assert p.startswith(b"AAAA")
    assert b"%1$p" in p and b"%5$p" in p


def test_rop_finder_on_real_elf():
    import syctf.modules.pwn.rop_finder as m

    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(file=sys.executable, max_per_gadget=5), ctx)
    assert rc == 0
    assert "ret" in ctx.cache.get("rop_gadgets", {})


def test_rop_finder_missing_file():
    import syctf.modules.pwn.rop_finder as m

    assert m.plugin.run(argparse.Namespace(file="/nope/nope.elf", max_per_gadget=5), _ctx()) == 2

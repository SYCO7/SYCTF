"""Forensics module tests — synthetic PNG/ZIP/PCAP, all stdlib."""

from __future__ import annotations

import argparse
import logging
import struct
import zipfile
import zlib
from pathlib import Path

from rich.console import Console

from syctf.core.plugin_loader import PluginLoader
from syctf.core.types import AppConfig, ExecutionContext
from syctf.modules.forensics.pcap_extract import iter_packets
from syctf.utils.png import decode_png

MODULES_ROOT = Path(__file__).resolve().parents[2] / "syctf" / "modules"


def _ctx() -> ExecutionContext:
    return ExecutionContext(
        config=AppConfig(),
        logger=logging.getLogger("test.forensics"),
        console=Console(),
        plugin_loader=None,
        cache={},
    )


def _make_png(width: int, height: int, channels: int, pixels: bytes) -> bytes:
    def chunk(typ: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + typ + data + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF)

    color = {1: 0, 3: 2, 4: 6}[channels]
    ihdr = struct.pack(">IIBBBBB", width, height, 8, color, 0, 0, 0)
    stride = width * channels
    raw = b"".join(b"\x00" + pixels[y * stride:(y + 1) * stride] for y in range(height))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def _embed_lsb(message: bytes, samples: int) -> bytes:
    bits = [(byte >> (7 - i)) & 1 for byte in message for i in range(8)]
    out = bytearray()
    for i in range(samples):
        base = 0x80  # arbitrary high bits
        bit = bits[i] if i < len(bits) else 0
        out.append((base & 0xFE) | bit)
    return bytes(out)


def test_png_decode_roundtrip():
    pixels = bytes(range(0, 12)) * 4  # 48 bytes -> 16 RGB pixels
    png = _make_png(4, 4, 3, pixels)
    img = decode_png(png)
    assert (img.width, img.height, img.channels) == (4, 4, 3)
    assert img.pixels == pixels


def test_stegano_extracts_lsb_flag(tmp_path):
    import syctf.modules.forensics.stegano as m

    flag = b"flag{stego_lsb_ok}"
    width, height, channels = 64, 1, 3
    samples = width * height * channels
    pixels = _embed_lsb(flag, samples)
    png = _make_png(width, height, channels, pixels)
    f = tmp_path / "s.png"
    f.write_bytes(png)

    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(file=str(f), bits=1), ctx)
    assert rc == 0
    assert ctx.cache.get("flag") == "flag{stego_lsb_ok}"


def _make_pcap(payloads: list[bytes]) -> bytes:
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body = b""
    for p in payloads:
        body += struct.pack("<IIII", 0, 0, len(p), len(p)) + p
    return header + body


def test_pcap_iter_and_flag(tmp_path):
    import syctf.modules.forensics.pcap_extract as m

    pcap = _make_pcap([b"GET /login HTTP/1.1\r\nAuthorization: Bearer abc\r\n", b"...flag{pcap_capture}..."])
    assert len(list(iter_packets(pcap))) == 2
    f = tmp_path / "c.pcap"
    f.write_bytes(pcap)
    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(file=str(f), grep=None), ctx)
    assert rc == 0
    assert ctx.cache.get("flag") == "flag{pcap_capture}"


def test_zip_crack_extracts_flag(tmp_path):
    # Plaintext zip: exercises the extract+scan path (the pwd loop reads it).
    import syctf.modules.forensics.zip_crack as m

    zpath = tmp_path / "a.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("note.txt", "the flag is flag{zip_inside}")
    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(file=str(zpath), wordlist=None), ctx)
    assert rc == 0
    assert ctx.cache.get("flag") == "flag{zip_inside}"


def test_loader_discovers_forensics():
    loader = PluginLoader(modules_roots=[MODULES_ROOT], logger=logging.getLogger("l"))
    found = loader.discover("forensics")
    assert {"stegano", "zip-crack", "pcap-extract"} <= set(found)

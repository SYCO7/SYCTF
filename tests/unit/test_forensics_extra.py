"""Tests for the added forensics/pwn modules: git, audio, metadata, heap."""

from __future__ import annotations

import argparse
import hashlib
import logging
import struct
import wave
import zlib
import zlib as _zlib
from pathlib import Path

from rich.console import Console

from syctf.core.types import AppConfig, ExecutionContext
from syctf.modules.pwn.heap_helper import align_chunk, fastbin_index, libc_base, tcache_index


def _ctx() -> ExecutionContext:
    return ExecutionContext(
        config=AppConfig(),
        logger=logging.getLogger("t"),
        console=Console(),
        plugin_loader=None,
        cache={},
    )


# ---------------------------------------------------------------- git forensics
def _write_git_object(git_dir: Path, typ: str, content: bytes) -> str:
    raw = f"{typ} {len(content)}\x00".encode() + content
    sha = hashlib.sha1(raw).hexdigest()
    d = git_dir / "objects" / sha[:2]
    d.mkdir(parents=True, exist_ok=True)
    (d / sha[2:]).write_bytes(zlib.compress(raw))
    return sha


def test_git_forensics_recovers_flag_from_dangling_blob(tmp_path):
    import syctf.modules.forensics.git_forensics as m

    git = tmp_path / "repo" / ".git"
    (git / "objects").mkdir(parents=True)
    (git / "logs").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    _write_git_object(git, "blob", b"AWS_KEY here flag{orphaned_commit_win}")
    _write_git_object(git, "commit", b"tree x\nauthor a\n\nrebased away flag{in_commit_msg}")
    (git / "logs" / "HEAD").write_text(
        "0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 a <a@b> 0 +0\tcommit\n"
    )
    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(path=str(tmp_path / "repo")), ctx)
    assert rc == 0
    assert "flag{orphaned_commit_win}" in str(ctx.cache.get("flag")) or ctx.cache.get("flag") in (
        "flag{orphaned_commit_win}", "flag{in_commit_msg}"
    )


# ---------------------------------------------------------------- audio stego
def test_audio_stego_lsb(tmp_path):
    import syctf.modules.forensics.audio_stego as m

    flag = b"flag{wav_lsb_hidden}"
    bits = [(byte >> (7 - j)) & 1 for byte in flag for j in range(8)]
    frames = bytearray()
    for i in range(len(bits) + 16):
        bit = bits[i] if i < len(bits) else 0
        frames += bytes([(0x40 & 0xFE) | bit, 0x00])   # 16-bit LE sample, low byte carries the bit
    path = tmp_path / "s.wav"
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(8000)
        wf.writeframes(bytes(frames))
    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(file=str(path), bits=1), ctx)
    assert rc == 0
    assert ctx.cache.get("flag") == "flag{wav_lsb_hidden}"


# ---------------------------------------------------------------- metadata
def _png_with_text(keyword: str, text: str) -> bytes:
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", _zlib.crc32(t + d) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = _zlib.compress(b"\x00\x00\x00\x00")
    text_chunk = chunk(b"tEXt", keyword.encode() + b"\x00" + text.encode())
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + text_chunk + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def test_metadata_png_text_flag(tmp_path):
    import syctf.modules.forensics.metadata as m
    from syctf.modules.forensics.metadata import png_text_chunks

    png = _png_with_text("Comment", "hidden: flag{exif_png_comment}")
    assert png_text_chunks(png) == [("Comment", "hidden: flag{exif_png_comment}")]
    f = tmp_path / "p.png"
    f.write_bytes(png)
    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(file=str(f)), ctx)
    assert rc == 0
    assert ctx.cache.get("flag") == "flag{exif_png_comment}"


# ---------------------------------------------------------------- heap math
def test_heap_math():
    assert align_chunk(24) == 0x20
    assert align_chunk(40) == 0x30          # glibc request2size(40)
    assert tcache_index(0x20) == 0
    assert tcache_index(0x90) == 7
    assert fastbin_index(0x20) == 0
    assert libc_base(0x7ffff7a0d000 + 0x1234, 0x1234) == 0x7ffff7a0d000

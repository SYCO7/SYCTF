"""Minimal, dependency-free PNG decoder (stdlib zlib only).

Supports 8-bit grayscale / gray+alpha / RGB / RGBA, non-interlaced — which
covers the vast majority of CTF stego images. Enough to pull pixel bytes for
LSB steganography without pulling in Pillow.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

_SIG = b"\x89PNG\r\n\x1a\n"
_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}  # color type -> samples/pixel


class PngError(ValueError):
    """Raised when the PNG cannot be decoded by this minimal reader."""


@dataclass(slots=True)
class PngImage:
    width: int
    height: int
    channels: int
    pixels: bytes  # row-major, `channels` bytes per pixel


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def decode_png(data: bytes) -> PngImage:
    if not data.startswith(_SIG):
        raise PngError("not a PNG")
    pos = len(_SIG)
    width = height = bit_depth = color_type = interlace = 0
    idat = bytearray()

    while pos + 8 <= len(data):
        length, ctype = struct.unpack_from(">I4s", data, pos)
        pos += 8
        chunk = data[pos:pos + length]
        pos += length + 4  # skip CRC
        if ctype == b"IHDR":
            width, height, bit_depth, color_type, _comp, _filt, interlace = struct.unpack(">IIBBBBB", chunk)
        elif ctype == b"IDAT":
            idat += chunk
        elif ctype == b"IEND":
            break

    if bit_depth != 8:
        raise PngError(f"unsupported bit depth {bit_depth} (only 8)")
    if interlace != 0:
        raise PngError("interlaced PNG unsupported")
    if color_type not in _CHANNELS:
        raise PngError(f"unsupported color type {color_type}")

    channels = _CHANNELS[color_type]
    stride = width * channels
    raw = zlib.decompress(bytes(idat))

    out = bytearray()
    prev = bytearray(stride)
    i = 0
    for _ in range(height):
        if i >= len(raw):
            break
        filter_type = raw[i]
        i += 1
        line = bytearray(raw[i:i + stride])
        i += stride
        for x in range(stride):
            a = line[x - channels] if x >= channels else 0
            b = prev[x]
            c = prev[x - channels] if x >= channels else 0
            if filter_type == 1:
                line[x] = (line[x] + a) & 0xFF
            elif filter_type == 2:
                line[x] = (line[x] + b) & 0xFF
            elif filter_type == 3:
                line[x] = (line[x] + (a + b) // 2) & 0xFF
            elif filter_type == 4:
                line[x] = (line[x] + _paeth(a, b, c)) & 0xFF
        out += line
        prev = line

    return PngImage(width=width, height=height, channels=channels, pixels=bytes(out))

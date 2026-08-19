"""Minimal binary AndroidManifest.xml (AXML) decoder.

Pure Python, no external deps. Parses the Android binary XML resource format
enough to recover element names and attribute name/value pairs — sufficient for
static APK security review (permissions, exported components, debuggable, etc.).

Degrades gracefully: on any malformed chunk it raises AxmlError, and callers
should fall back to raw scanning.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

# Chunk types
_STRING_POOL = 0x0001
_START_ELEMENT = 0x0102
_END_ELEMENT = 0x0103
_UTF8_FLAG = 1 << 8

# A small map of well-known android:* attribute resource IDs, used when an
# attribute's name string is empty (common in optimized APKs).
_ANDROID_ATTRS = {
    0x01010003: "name",
    0x01010006: "permission",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010280: "allowBackup",
    0x01010628: "usesCleartextTraffic",
}


class AxmlError(ValueError):
    """Raised when the AXML stream cannot be parsed."""


@dataclass(slots=True)
class AxmlElement:
    """One start element with resolved attributes."""

    tag: str
    attrs: dict[str, str] = field(default_factory=dict)


def _read_string_pool(data: bytes, offset: int) -> tuple[list[str], int]:
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
    if chunk_type != _STRING_POOL:
        raise AxmlError("expected string pool")
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
        "<IIIII", data, offset + 8
    )
    is_utf8 = bool(flags & _UTF8_FLAG)
    offsets_base = offset + 28
    strings: list[str] = []
    data_base = offset + strings_start
    for i in range(string_count):
        str_off = struct.unpack_from("<I", data, offsets_base + i * 4)[0]
        pos = data_base + str_off
        try:
            strings.append(_decode_string(data, pos, is_utf8))
        except Exception:  # noqa: BLE001
            strings.append("")
    return strings, offset + chunk_size


def _decode_string(data: bytes, pos: int, is_utf8: bool) -> str:
    if is_utf8:
        # UTF-8: char length (var), byte length (var), bytes, NUL.
        n, pos = _uleb_len8(data, pos)
        byte_len, pos = _uleb_len8(data, pos)
        return data[pos : pos + byte_len].decode("utf-8", "replace")
    # UTF-16LE: char length (var u16), then 2*len bytes.
    length, pos = _uleb_len16(data, pos)
    return data[pos : pos + length * 2].decode("utf-16-le", "replace")


def _uleb_len8(data: bytes, pos: int) -> tuple[int, int]:
    value = data[pos]
    pos += 1
    if value & 0x80:
        value = ((value & 0x7F) << 8) | data[pos]
        pos += 1
    return value, pos


def _uleb_len16(data: bytes, pos: int) -> tuple[int, int]:
    value = struct.unpack_from("<H", data, pos)[0]
    pos += 2
    if value & 0x8000:
        high = value & 0x7FFF
        low = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        value = (high << 16) | low
    return value, pos


def _str(strings: list[str], index: int) -> str:
    if 0 <= index < len(strings):
        return strings[index]
    return ""


def parse_axml(data: bytes) -> list[AxmlElement]:
    """Parse an AXML blob into a flat list of start elements."""

    if len(data) < 8:
        raise AxmlError("too short")
    magic = struct.unpack_from("<HH", data, 0)
    if magic[0] != 0x0003:  # RES_XML_TYPE
        raise AxmlError("not AXML")

    # String pool follows the 8-byte file header.
    strings, next_off = _read_string_pool(data, 8)

    elements: list[AxmlElement] = []
    offset = next_off
    size = len(data)
    while offset + 8 <= size:
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)
        if chunk_size < 8 or offset + chunk_size > size:
            break
        if chunk_type == _START_ELEMENT:
            elements.append(_parse_start_element(data, offset, strings))
        offset += chunk_size
    return elements


def _parse_start_element(data: bytes, offset: int, strings: list[str]) -> AxmlElement:
    # After the 8-byte chunk header + 8 bytes (lineNo, comment):
    body = offset + 16
    name_idx = struct.unpack_from("<I", data, body + 4)[0]
    attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, body + 8)
    tag = _str(strings, name_idx)
    attrs: dict[str, str] = {}
    attr_base = body + attr_start
    for i in range(attr_count):
        base = attr_base + i * 20
        if base + 20 > len(data):
            break
        ns_idx, an_idx, raw_val, typed = struct.unpack_from("<IIII", data, base)
        data_type = (typed >> 24) & 0xFF
        data_val = struct.unpack_from("<I", data, base + 16)[0]
        name = _str(strings, an_idx)
        if not name:
            name = _ANDROID_ATTRS.get(data_val, "") or f"attr_{an_idx}"
        attrs[name] = _resolve_value(strings, raw_val, data_type, data_val)
    return AxmlElement(tag=tag, attrs=attrs)


def _resolve_value(strings: list[str], raw_val: int, data_type: int, data_val: int) -> str:
    if raw_val != 0xFFFFFFFF:
        text = _str(strings, raw_val)
        if text:
            return text
    if data_type == 0x12:  # boolean
        return "true" if data_val != 0 else "false"
    if data_type == 0x10:  # int dec
        return str(data_val if data_val < 0x80000000 else data_val - 0x100000000)
    if data_type == 0x03:  # string
        return _str(strings, data_val)
    if data_type == 0x01:  # reference
        return f"@0x{data_val:08x}"
    return str(data_val)

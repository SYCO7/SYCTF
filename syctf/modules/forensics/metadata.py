"""File metadata extractor: PNG text chunks, JPEG EXIF/comment, printable
strings — then scan for flags and secrets. Pure stdlib.
"""

from __future__ import annotations

import argparse
import re
import struct
import zlib
from pathlib import Path

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.flags.detector import FlagDetector
from syctf.utils.secrets import scan_secrets


def png_text_chunks(data: bytes) -> list[tuple[str, str]]:
    """Return (keyword, text) from PNG tEXt / zTXt / iTXt chunks."""

    out: list[tuple[str, str]] = []
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return out
    pos = 8
    while pos + 8 <= len(data):
        length, ctype = struct.unpack_from(">I4s", data, pos)
        pos += 8
        chunk = data[pos:pos + length]
        pos += length + 4
        try:
            if ctype == b"tEXt":
                k, _, v = chunk.partition(b"\x00")
                out.append((k.decode("latin-1"), v.decode("latin-1")))
            elif ctype == b"zTXt":
                k, _, rest = chunk.partition(b"\x00")
                out.append((k.decode("latin-1"), zlib.decompress(rest[1:]).decode("latin-1")))
            elif ctype == b"iTXt":
                k, _, rest = chunk.partition(b"\x00")
                out.append((k.decode("latin-1"), rest.split(b"\x00")[-1].decode("utf-8", "ignore")))
        except (zlib.error, UnicodeDecodeError, IndexError):
            continue
        if ctype == b"IEND":
            break
    return out


def jpeg_segments(data: bytes) -> list[tuple[str, str]]:
    """Return (segment, printable-text) for JPEG COM and APPn segments."""

    out: list[tuple[str, str]] = []
    if not data.startswith(b"\xff\xd8"):
        return out
    pos = 2
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            pos += 1
            continue
        marker = data[pos + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        seg_len = struct.unpack_from(">H", data, pos + 2)[0]
        seg = data[pos + 4:pos + 2 + seg_len]
        if marker == 0xFE:  # COM
            out.append(("COM", seg.decode("latin-1", "ignore")))
        elif 0xE0 <= marker <= 0xEF:  # APPn (EXIF is APP1)
            runs = re.findall(rb"[\x20-\x7e]{4,}", seg)
            if runs:
                out.append((f"APP{marker-0xE0}", " | ".join(r.decode("ascii", "ignore") for r in runs[:20])))
        pos += 2 + seg_len
        if marker == 0xDA:  # start of scan -> stop
            break
    return out


class MetadataPlugin:
    """Pull metadata out of images/files and hunt for flags & secrets."""

    name = "metadata"
    description = "Extract PNG-text / JPEG-EXIF / comments + strings, scan for flags & secrets"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--file", required=True, help="Path to image/file")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        path = Path(args.file).expanduser()
        if not path.is_file():
            context.console.print("[bold red]File not found.[/bold red]")
            return 2

        data = path.read_bytes()
        detector = FlagDetector(custom_format=context.cache.get("flag_format"))
        fields = png_text_chunks(data) + jpeg_segments(data)

        if fields:
            table = Table(title=f"Metadata — {path.name}")
            table.add_column("Field", style="cyan", no_wrap=True)
            table.add_column("Value", style="white")
            for key, value in fields:
                table.add_row(key, value[:200])
            context.console.print(table)
        else:
            context.console.print("[dim]No PNG-text / JPEG-EXIF metadata; scanning strings.[/dim]")

        corpus = "\n".join(v for _, v in fields)
        corpus += "\n" + "\n".join(r.decode("ascii", "ignore") for r in re.findall(rb"[\x20-\x7e]{4,}", data))

        secrets = scan_secrets(corpus, source=path.name)
        if secrets:
            st = Table(title="Secrets")
            st.add_column("kind", style="red")
            st.add_column("value", style="yellow")
            for s in secrets:
                st.add_row(s.kind, s.value)
            context.console.print(st)

        found = {h.value for h in detector.scan(corpus) if h.real}
        if found:
            context.console.print("[bold green]Flags:[/bold green]")
            for flag in sorted(found):
                context.console.print(f"  - {flag}")
            context.cache["flag"] = sorted(found)[0]
        else:
            context.console.print("[dim]No flag in metadata/strings.[/dim]")
        return 0


plugin = MetadataPlugin()

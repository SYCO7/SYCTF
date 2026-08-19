"""LSB steganography extractor for PNG images (dependency-free)."""

from __future__ import annotations

import argparse
from pathlib import Path

from syctf.core.types import ExecutionContext
from syctf.flags.detector import FlagDetector
from syctf.utils.png import PngError, decode_png


def extract_lsb(pixels: bytes, channels: int, *, nbits: int = 1, skip_alpha: bool = False) -> bytes:
    """Assemble hidden bytes from the low bits of each sample (MSB-first)."""

    bits: list[int] = []
    for i, byte in enumerate(pixels):
        if skip_alpha and channels == 4 and (i % 4) == 3:
            continue
        for b in range(nbits):
            bits.append((byte >> b) & 1)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[i:i + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


class SteganoPlugin:
    """Pull LSB-hidden data out of a PNG and hunt for the flag."""

    name = "stegano"
    description = "LSB steganography extractor for PNG (no PIL needed)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--file", required=True, help="Path to PNG image")
        parser.add_argument("--bits", type=int, default=1, help="LSBs per sample to read (1-4)")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        path = Path(args.file).expanduser()
        if not path.is_file():
            context.console.print("[bold red]File not found.[/bold red]")
            return 2
        try:
            image = decode_png(path.read_bytes())
        except PngError as exc:
            context.console.print(f"[bold red]PNG decode failed:[/bold red] {exc}")
            return 1

        context.logger.info("forensics stegano file=%s %dx%d ch=%d", path, image.width, image.height, image.channels)
        detector = FlagDetector()
        nbits = max(1, min(int(args.bits), 4))

        for skip_alpha in (True, False):
            data = extract_lsb(image.pixels, image.channels, nbits=nbits, skip_alpha=skip_alpha)
            text = data.decode("latin-1", "ignore")
            for hit in detector.scan(text):
                if not hit.placeholder:
                    variant = "RGB only" if skip_alpha else "all channels"
                    context.console.print(f"[bold green]FLAG (LSB {nbits}-bit, {variant}):[/bold green] {hit.value}")
                    context.cache["flag"] = hit.value
                    return 0

        # No flag: show the most printable prefix so the operator can eyeball it.
        data = extract_lsb(image.pixels, image.channels, nbits=nbits, skip_alpha=False)
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:200])
        context.console.print(f"[bold]{image.width}x{image.height}, {image.channels}ch[/bold] — LSB {nbits}-bit prefix:")
        context.console.print(printable)
        context.console.print("[dim]No flag matched; try --bits 2/3 or inspect the prefix above.[/dim]")
        return 0


plugin = SteganoPlugin()

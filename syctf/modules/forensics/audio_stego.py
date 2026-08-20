"""WAV audio steganography: LSB extraction + string scan (stdlib `wave`)."""

from __future__ import annotations

import argparse
import re
import wave
from pathlib import Path

from syctf.core.types import ExecutionContext
from syctf.flags.detector import FlagDetector


def extract_lsb_bytes(samples: bytes, sample_width: int, *, nbits: int = 1, msb_first: bool = True) -> bytes:
    """Pull LSBs from the low byte of each sample and pack them into bytes."""

    step = max(1, sample_width)          # take the low byte of each sample
    bits: list[int] = []
    for i in range(0, len(samples), step):
        low = samples[i]
        for b in range(nbits):
            bits.append((low >> b) & 1)
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        chunk = bits[i:i + 8]
        if not msb_first:
            chunk = chunk[::-1]
        value = 0
        for bit in chunk:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


class AudioStegoPlugin:
    """Recover LSB-hidden data (and plain strings) from a WAV file."""

    name = "audio-stego"
    description = "WAV LSB steganography extractor + string scan"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--file", required=True, help="Path to .wav")
        parser.add_argument("--bits", type=int, default=1, help="LSBs per sample (1-4)")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        path = Path(args.file).expanduser()
        if not path.is_file():
            context.console.print("[bold red]File not found.[/bold red]")
            return 2

        detector = FlagDetector(custom_format=context.cache.get("flag_format"))
        nbits = max(1, min(int(args.bits), 4))

        try:
            with wave.open(str(path), "rb") as wf:
                params = wf.getparams()
                frames = wf.readframes(wf.getnframes())
        except (wave.Error, EOFError) as exc:
            context.console.print(f"[yellow]Not a readable WAV ({exc}); scanning raw bytes instead.[/yellow]")
            params = None
            frames = path.read_bytes()

        if params is not None:
            context.console.print(
                f"[bold]WAV[/bold] ch={params.nchannels} rate={params.framerate} "
                f"width={params.sampwidth*8}bit frames={params.nframes}"
            )
            for order in (True, False):
                data = extract_lsb_bytes(frames, params.sampwidth, nbits=nbits, msb_first=order)
                for hit in detector.scan(data.decode("latin-1", "ignore")):
                    if hit.real:
                        bit = "MSB-first" if order else "LSB-first"
                        context.console.print(f"[bold green]FLAG (LSB {nbits}-bit, {bit}):[/bold green] {hit.value}")
                        context.cache["flag"] = hit.value
                        return 0

        # fallback: printable strings anywhere in the file (metadata / appended data)
        runs = re.findall(rb"[\x20-\x7e]{4,}", path.read_bytes())
        text = "\n".join(r.decode("ascii", "ignore") for r in runs)
        for hit in detector.scan(text):
            if hit.real:
                context.console.print(f"[bold green]FLAG (strings):[/bold green] {hit.value}")
                context.cache["flag"] = hit.value
                return 0

        context.console.print(
            "[dim]No flag in LSB or strings. Try --bits 2/3, or a spectrogram tool "
            "(Audacity / Sonic Visualiser) for visual-frequency stego.[/dim]"
        )
        return 0


plugin = AudioStegoPlugin()

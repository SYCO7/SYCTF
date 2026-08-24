"""XOR cryptanalysis: single-byte brute force and repeating-key recovery."""

from __future__ import annotations

import argparse
import binascii

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.flags.detector import FlagDetector

# Rough English letter frequency for scoring candidate plaintext.
_FREQ = {c: f for c, f in zip("etaoinshrdlucmfwypvbgkjqxz", range(26, 0, -1))}


def _score(data: bytes) -> float:
    score = 0.0
    for b in data:
        ch = chr(b).lower()
        if ch in _FREQ:
            score += _FREQ[ch]
        elif b == 32:
            score += 20
        elif 32 <= b < 127:
            score += 1
        else:
            score -= 15
    return score / max(1, len(data))


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


class XorToolsPlugin:
    """Break single-byte and repeating-key XOR without external tools."""

    name = "xor-tools"
    description = "XOR solver: single-byte brute force + repeating-key (Hamming/frequency)"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--data", required=True, help="Ciphertext (hex by default)")
        parser.add_argument("--raw", action="store_true", help="Treat --data as raw text, not hex")
        parser.add_argument("--key", help="Known key (hex) to decrypt directly")
        parser.add_argument("--max-keysize", type=int, default=20, help="Max repeating-key size to test")

    def _load(self, args) -> bytes:
        if args.raw:
            return args.data.encode("latin-1", "ignore")
        return binascii.unhexlify("".join(args.data.split()))

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        try:
            data = self._load(args)
        except (binascii.Error, ValueError) as exc:
            context.console.print(f"[bold red]Bad input:[/bold red] {exc} (use --raw for text)")
            return 2
        if not data:
            context.console.print("[yellow]Empty input.[/yellow]")
            return 0

        detector = FlagDetector(custom_format=context.cache.get("flag_format"))

        if args.key:
            try:
                key = binascii.unhexlify("".join(args.key.split()))
            except binascii.Error:
                key = args.key.encode()
            self._emit(context, detector, _xor(data, key), f"key={key!r}")
            return 0

        # single-byte: gather every key whose plaintext holds a real flag, then
        # pick the most English-readable one. Ranking by score stops a garbage
        # "x{y}" at a low key from beating the real flag{...} at a higher key.
        flag_hits: list[tuple[float, int, str]] = []
        for k in range(256):
            candidate = _xor(data, bytes([k]))
            for hit in detector.scan(candidate.decode("latin-1", "ignore")):
                if hit.real:
                    flag_hits.append((_score(candidate), k, hit.value))
                    break
        if flag_hits:
            _, k, value = max(flag_hits, key=lambda t: t[0])
            context.console.print(f"[bold green]FLAG (single-byte key=0x{k:02x}):[/bold green] {value}")
            context.cache["flag"] = value
            return 0

        # single-byte (scored fallback)
        best = max(range(256), key=lambda k: _score(_xor(data, bytes([k]))))
        single = _xor(data, bytes([best]))
        self._emit(context, detector, single, f"single-byte key=0x{best:02x}", quiet=True)

        # repeating-key
        keysize = self._guess_keysize(data, max(2, int(args.max_keysize)))
        key = bytes(self._solve_column(data[col::keysize]) for col in range(keysize))
        repeating = _xor(data, key)

        table = Table(title="XOR candidates")
        table.add_column("Method", style="cyan")
        table.add_column("Score", style="white")
        table.add_column("Preview", style="green")
        table.add_row("single-byte", f"{_score(single):.1f}", single.decode('latin-1', 'ignore')[:60])
        table.add_row(f"repeating (ks={keysize})", f"{_score(repeating):.1f}", repeating.decode('latin-1', 'ignore')[:60])
        context.console.print(table)

        winner = single if _score(single) >= _score(repeating) else repeating
        label = "single-byte" if winner is single else f"repeating key={key!r}"
        self._emit(context, detector, winner, label)
        return 0

    def _guess_keysize(self, data: bytes, max_ks: int) -> int:
        best_ks, best_dist = 1, 1e9
        for ks in range(2, min(max_ks, len(data) // 2) + 1):
            blocks = [data[i * ks:(i + 1) * ks] for i in range(4) if len(data) >= (i + 1) * ks]
            if len(blocks) < 2:
                continue
            dists = [_hamming(blocks[i], blocks[i + 1]) / ks for i in range(len(blocks) - 1)]
            avg = sum(dists) / len(dists)
            if avg < best_dist:
                best_dist, best_ks = avg, ks
        return best_ks

    def _solve_column(self, column: bytes) -> int:
        return max(range(256), key=lambda k: _score(_xor(column, bytes([k]))))

    def _emit(self, context, detector, plaintext: bytes, label: str, *, quiet: bool = False) -> None:
        text = plaintext.decode("latin-1", "ignore")
        for hit in detector.scan(text):
            if hit.real:
                context.console.print(f"[bold green]FLAG ({label}):[/bold green] {hit.value}")
                context.cache["flag"] = hit.value
                return
        if not quiet:
            context.console.print(f"[bold]Best ({label}):[/bold] {text[:200]!r}")


plugin = XorToolsPlugin()

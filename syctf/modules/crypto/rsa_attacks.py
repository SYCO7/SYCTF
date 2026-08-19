"""RSA attack toolkit: factor n and recover the plaintext.

Chains the attacks that crack most CTF RSA: known p/q or d, factordb lookup,
Fermat (close primes), Pollard rho, Wiener (small d), and low-exponent e-th
root. Pure Python — no gmpy2 required.
"""

from __future__ import annotations

import argparse

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.flags.detector import FlagDetector
from syctf.utils.mathx import (
    fermat_factor,
    iroot,
    long_to_bytes,
    modinv,
    parse_int,
    pollard_rho,
    wiener_attack,
)
from syctf.utils.net_utils import http_json


def _factordb(n: int, timeout: float) -> tuple[int, int] | None:
    data = http_json("http://factordb.com/api", params={"query": str(n)}, timeout=timeout)
    if not isinstance(data, dict) or data.get("status") != "FF":
        return None
    factors: list[int] = []
    for entry in data.get("factors", []):
        try:
            factors.extend([int(entry[0])] * int(entry[1]))
        except (ValueError, IndexError, TypeError):
            continue
    return (factors[0], factors[1]) if len(factors) == 2 else None


class RsaAttacksPlugin:
    """Recover RSA plaintext through a chain of classic attacks."""

    name = "rsa-attacks"
    description = "RSA solver: factordb, Fermat, Pollard rho, Wiener, low-exponent root"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--n", required=True, help="Modulus n (dec or 0x)")
        parser.add_argument("--e", default="65537", help="Public exponent e")
        parser.add_argument("--c", help="Ciphertext c (dec or 0x)")
        parser.add_argument("--p", help="Known prime p")
        parser.add_argument("--q", help="Known prime q")
        parser.add_argument("--d", help="Known private exponent d")

    def _attack(self, n: int, e: int, timeout: float, context: ExecutionContext):
        """Return (p, q, d, method); any element may be None."""

        context.console.print("[dim]factoring n ...[/dim]")
        fd = _factordb(n, timeout)
        if fd:
            return fd[0], fd[1], None, "factordb"
        fm = fermat_factor(n, max_iter=200_000)
        if fm:
            return fm[0], fm[1], None, "Fermat (close primes)"
        d_wiener = wiener_attack(e, n)
        if d_wiener is not None:
            return None, None, d_wiener, "Wiener (small d)"
        factor = pollard_rho(n, max_iter=500_000)
        if factor and 1 < factor < n:
            return factor, n // factor, None, "Pollard rho"
        return None, None, None, ""

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        try:
            n = parse_int(args.n)
            e = parse_int(args.e)
            c = parse_int(args.c) if args.c else None
            p = parse_int(args.p) if args.p else None
            q = parse_int(args.q) if args.q else None
            d = parse_int(args.d) if args.d else None
        except ValueError as exc:
            context.console.print(f"[bold red]Bad integer input:[/bold red] {exc}")
            return 2

        method = "provided"
        timeout = max(10.0, float(getattr(context.config, "request_timeout", 12.0)))

        # Low public exponent: plaintext is the exact e-th root of c (no padding).
        if c is not None and d is None and p is None and q is None and e <= 7:
            root, exact = iroot(c, e)
            if exact:
                self._report(context, value=root, method=f"low-exponent e={e} root")
                return 0

        # Recover d (directly, from p&q, or via an attack).
        if d is None and (p is None or q is None):
            ap, aq, ad, amethod = self._attack(n, e, timeout, context)
            p = p or ap
            q = q or aq
            if ad is not None:
                d = ad
            method = amethod or method

        if d is None and p and q:
            try:
                d = modinv(e, (p - 1) * (q - 1))
                if method == "provided":
                    method = "known p,q"
            except ValueError:
                context.console.print("[yellow]Recovered factors but e not invertible mod phi.[/yellow]")

        if d is None:
            context.console.print("[bold red]Could not factor n or recover d with available attacks.[/bold red]")
            return 1

        table = Table(title="RSA recovery", show_header=False)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("method", method)
        if p:
            table.add_row("p", str(p))
        if q:
            table.add_row("q", str(q))
        table.add_row("d", str(d))
        context.console.print(table)

        if c is not None:
            self._report(context, value=pow(c, d, n), method="decrypt")
        return 0

    def _report(self, context: ExecutionContext, *, value: int, method: str) -> None:
        data = long_to_bytes(value)
        printable = data.decode("latin-1", "ignore")
        context.console.print(f"[bold green]Plaintext ({method}):[/bold green]")
        context.console.print(f"  int  : {value}")
        context.console.print(f"  bytes: {printable!r}")
        for hit in FlagDetector().scan(printable):
            if hit.real:
                context.console.print(f"[bold green]FLAG:[/bold green] {hit.value}")
                context.cache["flag"] = hit.value


plugin = RsaAttacksPlugin()

"""Number-theory helpers for crypto analyzers (pure Python, no gmpy2)."""

from __future__ import annotations

import math


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclid: return (g, x, y) with a*x + b*y = g."""

    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m; raises ValueError if none exists."""

    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def iroot(n: int, k: int) -> tuple[int, bool]:
    """Integer k-th root of n; return (root, exact)."""

    if n < 0:
        raise ValueError("negative radicand")
    if n == 0:
        return 0, True
    lo, hi = 0, 1 << ((n.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid**k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo**k == n


def is_probable_prime(n: int) -> bool:
    """Deterministic Miller-Rabin for 64-bit-ish, strong for CTF sizes."""

    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def fermat_factor(n: int, max_iter: int = 1_000_000) -> tuple[int, int] | None:
    """Factor n when p and q are close (Fermat's method)."""

    a, _exact = iroot(n, 2)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b, exact = iroot(b2, 2)
        if exact:
            return a - b, a + b
        a += 1
    return None


def pollard_rho(n: int, max_iter: int = 2_000_000) -> int | None:
    """Return a non-trivial factor of n, or None."""

    if n % 2 == 0:
        return 2
    x = y = 2
    c = 1
    d = 1
    count = 0
    while d == 1 and count < max_iter:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = math.gcd(abs(x - y), n)
        count += 1
    return d if 1 < d < n else None


def long_to_bytes(value: int) -> bytes:
    """Convert a non-negative integer to big-endian bytes."""

    if value == 0:
        return b"\x00"
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


def parse_int(text: str) -> int:
    """Parse a decimal or 0x-hex integer string."""

    text = str(text).strip().replace("_", "").replace(" ", "")
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text)


def wiener_attack(e: int, n: int) -> int | None:
    """Recover private exponent d via Wiener's attack (small d)."""

    def continued_fraction(a: int, b: int) -> list[int]:
        cf = []
        while b:
            cf.append(a // b)
            a, b = b, a % b
        return cf

    def convergents(cf: list[int]):
        num0, num1 = 0, 1
        den0, den1 = 1, 0
        for coeff in cf:
            num0, num1 = num1, coeff * num1 + num0
            den0, den1 = den1, coeff * den1 + den0
            yield num1, den1

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        root, exact = iroot(disc, 2)
        if exact and (b + root) % 2 == 0:
            return d
    return None

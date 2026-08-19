"""Crypto analyzer tests — RSA + XOR, fully offline (no factordb needed)."""

from __future__ import annotations

import argparse
import logging

from rich.console import Console

from syctf.core.types import AppConfig, ExecutionContext
from syctf.utils.mathx import iroot, long_to_bytes, modinv, wiener_attack


def _ctx() -> ExecutionContext:
    return ExecutionContext(
        config=AppConfig(),
        logger=logging.getLogger("test.crypto"),
        console=Console(),
        plugin_loader=None,
        cache={},
    )


def test_mathx_iroot_and_modinv():
    assert iroot(27, 3) == (3, True)
    assert iroot(28, 3) == (3, False)
    assert modinv(3, 11) == 4


def test_rsa_known_pq_decrypt():
    import syctf.modules.crypto.rsa_attacks as m

    p, q, e = 61, 53, 17
    n = p * q
    d = modinv(e, (p - 1) * (q - 1))
    msg = 42
    c = pow(msg, e, n)
    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(n=str(n), e=str(e), c=str(c), p=str(p), q=str(q), d=None), ctx)
    assert rc == 0  # decrypts without error


def test_rsa_low_exponent_root():
    import syctf.modules.crypto.rsa_attacks as m

    e = 3
    msg = int.from_bytes(b"flag{rsa}", "big")
    c = msg**e  # unpadded, tiny modulus not needed for root attack
    n = c + 12345  # n > c so pow path not used; low-exp root triggers
    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(n=str(n), e="3", c=str(c), p=None, q=None, d=None), ctx)
    assert rc == 0
    assert ctx.cache.get("flag") == "flag{rsa}"


def test_wiener_attack_recovers_d():
    # Construct an RSA key with small d so Wiener applies.
    p = 1009
    q = 3643
    n = p * q
    phi = (p - 1) * (q - 1)
    d = 17
    e = modinv(d, phi)
    recovered = wiener_attack(e, n)
    assert recovered == d


def test_xor_single_byte_flag():
    import syctf.modules.crypto.xor_tools as m

    key = 0x42
    pt = b"flag{xor_single_byte}"
    ct = bytes(b ^ key for b in pt).hex()
    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(data=ct, raw=False, key=None, max_keysize=8), ctx)
    assert rc == 0
    assert ctx.cache.get("flag") == "flag{xor_single_byte}"

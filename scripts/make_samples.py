#!/usr/bin/env python3
"""Generate sample CTF challenges for the manual feature walkthrough.

Writes to examples/challenges/. Everything is solvable offline so every demo
step produces a real, screenshot-worthy flag.

    python scripts/make_samples.py
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import zipfile
import zlib
from pathlib import Path

from syctf.utils.mathx import is_probable_prime

OUT = Path(__file__).resolve().parents[1] / "examples" / "challenges"


def _next_prime(n: int) -> int:
    n += 1 if n % 2 == 0 else 0
    while not is_probable_prime(n):
        n += 2
    return n


def crypto_b64() -> None:
    inner = base64.b64encode(b"flag{base64_layers_are_fun}")
    (OUT / "crypto_b64.txt").write_bytes(base64.b64encode(inner))


def crypto_xor() -> None:
    pt = b"flag{single_byte_xor_0x42}"
    (OUT / "crypto_xor.hex").write_text(bytes(b ^ 0x42 for b in pt).hex())


def crypto_rsa() -> None:
    p = _next_prime(10**30 + 31337)
    q = _next_prime(p + 424242)                 # close primes -> Fermat
    n, e = p * q, 65537
    m = int.from_bytes(b"flag{rsa_fermat_close_primes}", "big")
    c = pow(m, e, n)
    (OUT / "crypto_rsa.txt").write_text(f"n = {n}\ne = {e}\nc = {c}\n")


def forensics_stego() -> None:
    flag = b"flag{lsb_stego_hidden_pixels}"
    bits = [(byte >> (7 - i)) & 1 for byte in flag for i in range(8)]
    w, h, ch = 96, 1, 3
    samples = w * h * ch
    px = bytes(((0x80 & 0xFE) | (bits[i] if i < len(bits) else 0)) for i in range(samples))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"\x00" + px)) + chunk(b"IEND", b"")
    (OUT / "forensics_stego.png").write_bytes(png)


def forensics_pcap() -> None:
    payloads = [
        b"GET /login HTTP/1.1\r\nHost: ctf\r\nAuthorization: Basic YWRtaW46cw==\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\nwelcome, here is flag{sniffed_from_the_wire}\n",
    ]
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body = b"".join(struct.pack("<IIII", 0, 0, len(p), len(p)) + p for p in payloads)
    (OUT / "forensics_capture.pcap").write_bytes(header + body)


def forensics_zip() -> None:
    with zipfile.ZipFile(OUT / "forensics_secret.zip", "w") as zf:
        zf.writestr("readme.txt", "nothing to see")
        zf.writestr("flag.txt", "flag{zip_archive_recovered}")


def web_jwt() -> None:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"user": "guest", "admin": False}).encode()).rstrip(b"=").decode()
    sig = hmac.new(b"secret", f"{header}.{payload}".encode(), hashlib.sha256).digest()
    token = f"{header}.{payload}." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    (OUT / "web_token.jwt").write_text(token)


def mobile_apk() -> None:
    with zipfile.ZipFile(OUT / "mobile_app.apk", "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest package='com.demo.ctf'/>")
        zf.writestr("res/values/strings.xml", "<resources>AKIAIOSFODNN7EXAMPLE https://api.demo.ctf/v1</resources>")
        zf.writestr("classes.dex", b"junk...flag{apk_reverse_engineered}...javax/crypto/Cipher Runtime.exec okhttp")


def decoy_file() -> None:
    (OUT / "misc_decoy.bin").write_bytes(
        b"\x00 noise flag{fake_try_harder} noise noise "
        b"flag{decoy_nice_try} ... deeper ... flag{the_real_one_2024} end\x01"
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for fn in (crypto_b64, crypto_xor, crypto_rsa, forensics_stego, forensics_pcap,
               forensics_zip, web_jwt, mobile_apk, decoy_file):
        fn()
    for f in sorted(OUT.iterdir()):
        print(f"  {f.relative_to(OUT.parents[1])}  ({f.stat().st_size} B)")
    print(f"\nwrote {len(list(OUT.iterdir()))} sample challenges to {OUT}")


if __name__ == "__main__":
    main()

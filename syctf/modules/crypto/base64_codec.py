"""Base64 encoder/decoder module."""

from __future__ import annotations

import argparse
import base64

from syctf.core.types import ExecutionContext


class Base64CodecPlugin:
    """Handle Base64 encoding and decoding for CTF payloads."""

    name = "base64"
    description = "Encode or decode Base64 strings"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register plugin arguments."""

        parser.add_argument("action", choices=["encode", "decode"], help="Operation mode")
        parser.add_argument("--text", required=True, help="Input text")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Execute Base64 operation."""

        if args.action == "encode":
            result = base64.b64encode(args.text.encode("utf-8")).decode("utf-8")
        else:
            decoded = base64.b64decode(args.text.encode("utf-8"), validate=True)
            result = decoded.decode("utf-8", errors="replace")

        context.console.print(f"[bold cyan]Result:[/bold cyan] {result}")
        return 0


plugin = Base64CodecPlugin()

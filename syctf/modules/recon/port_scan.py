"""Threaded safe TCP port scanner for CTF reconnaissance."""

from __future__ import annotations

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from syctf.core.types import ExecutionContext
from syctf.core.validation import validate_hostname, validate_port_range


class PortScanPlugin:
    """Scan a host over a user-provided TCP port range."""

    name = "port-scan"
    description = "Threaded TCP port scanner with timeout safeguards"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register plugin arguments."""

        parser.add_argument("--host", required=True, help="Target host or IP")
        parser.add_argument("--start-port", type=int, default=1, help="Range start")
        parser.add_argument("--end-port", type=int, default=1024, help="Range end")
        parser.add_argument("--threads", type=int, default=100, help="Worker thread count")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        """Execute threaded TCP connect scan."""

        host = validate_hostname(args.host)
        start_port, end_port = validate_port_range(args.start_port, args.end_port)
        thread_count = max(1, min(int(args.threads), context.config.max_threads))
        timeout = context.config.connect_timeout

        context.logger.info(
            "Recon port-scan host=%s start=%d end=%d threads=%d",
            host,
            start_port,
            end_port,
            thread_count,
        )

        ports = list(range(start_port, end_port + 1))
        open_ports: list[int] = []

        def scan_port(port: int) -> tuple[int, bool]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return port, result == 0

        with ThreadPoolExecutor(max_workers=thread_count) as pool:
            futures = [pool.submit(scan_port, port) for port in ports]
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)

        if not open_ports:
            context.console.print("[yellow]No open ports discovered in the selected range.[/yellow]")
            return 0

        context.console.print("[bold green]Open ports:[/bold green]")
        for port in sorted(open_ports):
            context.console.print(f"  - {port}")
        return 0


plugin = PortScanPlugin()

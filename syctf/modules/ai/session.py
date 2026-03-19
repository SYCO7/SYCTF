"""Ollama-powered local AI session for SYCTF interactive shell."""

from __future__ import annotations

import argparse
import concurrent.futures
import logging
import re
import time
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

from syctf.ai.client import (
    get_ai_connection_diagnostics,
    get_ollama_client,
)
from syctf.modules.ai.category_detector import (
    detect_category,
    render_detection,
    suggested_workflow,
)
from syctf.modules.ai.exploit_generator import generate_exploit
from syctf.modules.ai.auto_decode import run_auto_decode_command
from syctf.core.paths import get_logs_dir
from syctf.core.workspace_state import append_ai_note

SYSTEM_PROMPT = """
You are SYCTF AI, a specialized CTF assistant for terminal workflows.

Mandatory behavior:
1. Detect likely challenge category (web, crypto, pwn, forensics, reverse).
2. Propose a clear attack workflow with concise numbered steps.
3. Suggest practical tools and explain why each is useful.
4. Provide payload skeletons or command templates when relevant.
5. Never fabricate or hallucinate flags.
6. If data is insufficient, ask for the exact artifact required.
""".strip()


class AISession:
    """Stateful AI conversation session for shell-only command routing."""

    def __init__(
        self,
        console: Console,
        app_logger: logging.Logger,
        model: str = "deepseek-coder:6.7b",
        *,
        execution_context: Any | None = None,
        plugin_loader: Any | None = None,
        ai_auto_run: bool = True,
    ) -> None:
        """Initialize AI session services and conversation state."""

        self.console = console
        self.app_logger = app_logger
        self.model = model
        self.execution_context = execution_context
        self.plugin_loader = plugin_loader
        self.ai_auto_run = ai_auto_run
        self.ai_logger = self._build_ai_logger(get_logs_dir() / "ai.log")
        self.messages: list[dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.auto_run_min_confidence = 0.80
        self.auto_run_threshold = 0.85
        self.auto_run_timeout_seconds = 20.0
        self.stream_timeout_seconds = 45.0
        self.category_module_map: dict[str, str] = {
            "crypto": "misc/smart-decode",
            "pwn": "pwn/elf-analyze",
            "web": "web/param-fuzzer",
            "rev": "rev/strings-analyzer",
        }

    @staticmethod
    def _build_ai_logger(log_file: Path) -> logging.Logger:
        """Create dedicated logger that appends to logs/ai.log."""

        log_file.parent.mkdir(parents=True, exist_ok=True)
        logger = logging.getLogger("syctf.ai.session")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        logger.propagate = False

        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
        return logger

    def _show_connection_diagnostics(self) -> bool:
        """Render connection diagnostics and gate AI startup readiness."""

        diagnostics = get_ai_connection_diagnostics(model=self.model)
        connected = diagnostics.connected_host or "unavailable"
        latency = (
            f"{diagnostics.latency_ms:.1f} ms"
            if diagnostics.latency_ms is not None
            else "unavailable"
        )
        model_state = "available" if diagnostics.model_available else "missing"

        self.console.print(
            Panel(
                f"[green]✔ Connected host:[/green] {connected}\n"
                f"[green]✔ Latency:[/green] {latency}\n"
                f"[green]✔ Model availability:[/green] {model_state}",
                title="AI Diagnostics",
                border_style="cyan",
            )
        )

        if diagnostics.connected_host is None:
            self.ai_logger.warning("ollama resolver failed: no reachable host")
            self.console.print("AI engine offline — continuing without AI.", markup=False)
            return False

        if not diagnostics.model_available:
            self.console.print(f"Model missing: {self.model}", markup=False)
            self.console.print(
                f"Available models: {diagnostics.available_models}",
                markup=False,
            )
            self.ai_logger.warning(
                "configured model missing host=%s model=%s available=%s",
                diagnostics.connected_host,
                self.model,
                diagnostics.available_models,
            )
            self.console.print("AI engine offline — continuing without AI.", markup=False)
            return False

        return True

    def start(self, mode: str = "chat") -> int:
        """Run AI prompt loop until user exits back to main shell."""

        if mode.startswith("exploit"):
            self.console.print(
                "[yellow]Usage:[/yellow] ai exploit <binary_path>\n"
                "Example: ai exploit ./vuln"
            )
            return 1

        if not self._show_connection_diagnostics():
            return 0

        self.console.print(Rule("[bold cyan]SYCTF AI MODE[/bold cyan]", style="cyan"))
        self.console.print("[cyan]Type exit to return to SYCTF shell.[/cyan]")
        self.console.print("[cyan]Multi-line enabled: submit with an empty line.[/cyan]")

        while True:
            prompt = self._read_multiline()
            if prompt is None:
                self.console.print(Rule(style="cyan"))
                return 0

            if prompt.lower() == "exit":
                self.console.print(Rule(style="cyan"))
                return 0
            if not prompt:
                continue
            if len(prompt) > 4000:
                self.console.print("[yellow]Input too long (max 4000 chars).[/yellow]")
                continue

            if mode == "decode":
                self.log_query(prompt, mode)
                self._run_decode_pipeline(prompt)
                continue

            if mode == "chat":
                self._detect_and_suggest(prompt)

            self.log_query(prompt, mode)
            self.stream_chat(prompt, mode=mode)

    def _detect_and_suggest(self, prompt: str) -> None:
        """Detect likely category from challenge description and print workflow hints."""

        detection = detect_category(prompt, model=self.model)
        render_detection(self.console, detection)

        category = str(detection.get("category", "misc"))
        confidence = float(detection.get("confidence", 0.0))
        workflow = suggested_workflow(category)

        self.console.print("[bold cyan]Suggested workflow:[/bold cyan]")
        for command in workflow:
            self.console.print(f"  - {command}")

        self.ai_logger.info(
            "category=%s confidence=%.2f reasoning=%s",
            category,
            confidence,
            str(detection.get("reasoning", "")),
        )

        self._maybe_auto_execute(category=category, confidence=confidence, input_text=prompt)

    def _maybe_auto_execute(self, *, category: str, confidence: float, input_text: str) -> None:
        """Optionally auto-run mapped module when classifier confidence is high."""

        module_key = self.category_module_map.get(category)
        if module_key is None:
            return
        if confidence <= self.auto_run_min_confidence:
            return
        if confidence < self.auto_run_threshold:
            self.console.print(
                f"[yellow]Auto-run not offered:[/yellow] confidence {confidence:.2f} < "
                f"{self.auto_run_threshold:.2f}"
            )
            return

        if not self.ai_auto_run:
            self.console.print("[yellow]Auto-run disabled in config (ai_auto_run=false).[/yellow]")
            return

        plugin = self._resolve_plugin(module_key)
        if plugin is None:
            self.console.print(
                f"[yellow]Auto-run target unavailable:[/yellow] {module_key} not discovered"
            )
            return

        module_args = self._build_auto_args(module_key, input_text)
        if module_args is None:
            self.console.print(
                f"[yellow]Auto-run skipped:[/yellow] unable to derive required inputs for {module_key}"
            )
            return

        if not self._confirm_auto_run():
            self.console.print("[yellow]Auto-run canceled by user.[/yellow]")
            return

        self.console.print(
            Panel(
                f"Running {getattr(plugin, 'name', module_key)}...",
                title="Auto Module Execution",
                border_style="cyan",
            )
        )
        self._execute_plugin_safely(module_key, plugin, module_args)

    def _resolve_plugin(self, module_key: str) -> Any | None:
        """Resolve mapped module key (category/name) via plugin loader."""

        if self.plugin_loader is None or "/" not in module_key:
            return None

        category, module_name = module_key.split("/", 1)
        try:
            plugins = self.plugin_loader.discover(category)
        except Exception as exc:  # noqa: BLE001
            self.ai_logger.exception("plugin discovery failed for %s: %s", category, exc)
            return None
        return plugins.get(module_name)

    def _build_auto_args(self, module_key: str, input_text: str) -> argparse.Namespace | None:
        """Build module argument namespace from challenge text."""

        if module_key == "misc/smart-decode":
            return argparse.Namespace(text=input_text.strip(), max_depth=5, _help=False)

        if module_key == "pwn/elf-analyze":
            binary_path = self._extract_binary_path(input_text)
            if not binary_path:
                return None
            return argparse.Namespace(binary_path=binary_path, timeout=10.0, _help=False)

        if module_key == "web/param-fuzzer":
            url = self._extract_url(input_text)
            return argparse.Namespace(url=url, params=None, payload="' OR '1'='1", text=input_text, _help=False)

        if module_key == "rev/strings-analyzer":
            return argparse.Namespace(target=input_text.strip(), min_len=4, limit=50, _help=False)

        return None

    def _extract_url(self, text: str) -> str | None:
        """Extract first URL from text for web automation modules."""

        match = re.search(r"https?://[^\s'\"]+", text, re.IGNORECASE)
        return match.group(0) if match else None

    def _extract_binary_path(self, text: str) -> str | None:
        """Extract existing ELF-like path from free-form input text."""

        tokens = [token.strip("'\"") for token in text.split() if token.strip()]
        for token in tokens:
            candidate = Path(token)
            if not candidate.exists() or not candidate.is_file():
                continue
            try:
                with candidate.open("rb") as handle:
                    if handle.read(4) == b"\x7fELF":
                        return str(candidate)
            except OSError:
                continue
        return None

    def _confirm_auto_run(self) -> bool:
        """Prompt user confirmation before launching auto module execution."""

        try:
            answer = input("Auto-run suggested module? (y/n) ").strip().lower()
        except EOFError:
            return False
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Auto-run prompt interrupted.[/yellow]")
            return False
        return answer in {"y", "yes"}

    def _execute_plugin_safely(self, module_key: str, plugin: Any, module_args: argparse.Namespace) -> None:
        """Run module with timeout, exception shielding, and Ctrl+C handling."""

        if self.execution_context is None:
            self.console.print("[yellow]Auto-run unavailable: execution context missing.[/yellow]")
            return

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(plugin.run, module_args, self.execution_context)
        deadline = time.monotonic() + self.auto_run_timeout_seconds

        try:
            while True:
                try:
                    result = future.result(timeout=0.2)
                    code = int(result) if isinstance(result, int) else 0
                    if code == 0:
                        self.console.print(f"[green]Auto-run completed:[/green] {module_key}")
                    else:
                        self.console.print(
                            f"[yellow]Auto-run finished with exit code {code}:[/yellow] {module_key}"
                        )
                    return
                except concurrent.futures.TimeoutError:
                    if time.monotonic() >= deadline:
                        future.cancel()
                        self.console.print(
                            f"[bold red]Auto-run timed out after {self.auto_run_timeout_seconds:.0f}s:[/bold red] "
                            f"{module_key}"
                        )
                        self.ai_logger.warning("auto-run timeout module=%s", module_key)
                        return
                except Exception as exc:  # noqa: BLE001
                    self.console.print(f"[bold red]Auto-run failed:[/bold red] {exc}")
                    self.ai_logger.exception("auto-run failure module=%s err=%s", module_key, exc)
                    return
        except KeyboardInterrupt:
            future.cancel()
            self.console.print("\n[yellow]Auto-run canceled by user (CTRL+C).[/yellow]")
            self.ai_logger.warning("auto-run canceled by user module=%s", module_key)
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    def run_exploit_mode(self, binary_path: str, remote: str | None = None) -> int:
        """Run exploit generation mode for a target ELF binary path."""

        if not self._show_connection_diagnostics():
            return 0

        try:
            self.ai_logger.info("mode=exploit target=%s remote=%s", binary_path, remote)
            self.app_logger.info("AI exploit generator target=%s remote=%s", binary_path, remote)
            generate_exploit(
                binary_path,
                remote=remote,
                workspace_root=(
                    self.execution_context.cache.get("workspace_root")
                    if self.execution_context is not None
                    else None
                ),
                console=self.console,
                cache=(
                    self.execution_context.cache
                    if self.execution_context is not None
                    else None
                ),
            )
            return 0
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[bold red]Exploit generation failed:[/bold red] {exc}")
            self.ai_logger.exception("exploit generation failure: %s", exc)
            return 1

    def _read_multiline(self) -> str | None:
        """Read multi-line prompt and return final text."""

        lines: list[str] = []
        while True:
            try:
                line = input("SYCTF AI > ")
            except EOFError:
                return None

            stripped = line.strip()
            if not lines and stripped.lower() == "exit":
                return "exit"

            if line == "":
                if not lines:
                    return ""
                return "\n".join(lines).strip()
            lines.append(line)

    def log_query(self, prompt: str, mode: str) -> None:
        """Log user prompt metadata and content for auditing."""

        self.ai_logger.info(
            "mode=%s utc=%s prompt=%s",
            mode,
            datetime.now(UTC).isoformat(),
            prompt.replace("\n", "\\n"),
        )
        self.app_logger.info("AI query routed in mode=%s", mode)
        if self.execution_context is not None:
            append_ai_note(
                self.execution_context.cache,
                title=f"AI Query ({mode})",
                content=prompt,
            )

    def stream_chat(self, prompt: str, *, mode: str = "chat") -> None:
        """Stream AI response token-by-token to terminal output."""

        user_payload = f"Mode: {mode}\n\n{prompt}" if mode != "chat" else prompt
        self.messages.append({"role": "user", "content": user_payload})

        self.console.print(Rule("[bold magenta]AI Response[/bold magenta]", style="magenta"))

        assistant_chunks: list[str] = []
        stream_started = time.monotonic()
        try:
            client = get_ollama_client(timeout=self.stream_timeout_seconds)
            stream = client.chat(model=self.model, messages=self.messages, stream=True)
            stream_iter = iter(stream)

            with self.console.status("[magenta]Thinking...[/magenta]", spinner="dots"):
                first = next(stream_iter, None)

            if first is None:
                self.console.print("[yellow]No response tokens received.[/yellow]")
                return

            first_token = first.get("message", {}).get("content", "")
            if first_token:
                assistant_chunks.append(first_token)
                self.console.print(f"[bold magenta]AI>[/bold magenta] {first_token}", end="")

            for chunk in stream_iter:
                if time.monotonic() - stream_started > self.stream_timeout_seconds:
                    self.console.print("\n[yellow]AI stream timeout reached; response truncated.[/yellow]")
                    break
                token = chunk.get("message", {}).get("content", "")
                if not token:
                    continue
                assistant_chunks.append(token)
                self.console.print(token, end="")

            self.console.print()
            self.console.print(Rule(style="magenta"))
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[bold red]AI stream error:[/bold red] {exc}")
            self.console.print("AI engine offline — continuing without AI.", markup=False)
            self.ai_logger.exception("stream_chat failure: %s", exc)
            return

        self.messages.append({"role": "assistant", "content": "".join(assistant_chunks)})
        if self.execution_context is not None and assistant_chunks:
            append_ai_note(
                self.execution_context.cache,
                title=f"AI Response ({mode})",
                content="".join(assistant_chunks),
            )

    def _run_decode_pipeline(self, payload: str) -> None:
        """Run deterministic decode-first pipeline for ai decode mode."""

        try:
            run_auto_decode_command(
                payload,
                console=self.console,
                cache=(self.execution_context.cache if self.execution_context is not None else None),
                model=self.model,
                max_depth=4,
                top_n=8,
                llm_threshold=0.72,
                script=True,
            )
        except Exception as exc:  # noqa: BLE001
            self.console.print(f"[bold red]AI decode pipeline failed:[/bold red] {exc}")
            self.ai_logger.exception("decode pipeline failure: %s", exc)

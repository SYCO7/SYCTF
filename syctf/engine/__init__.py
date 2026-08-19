"""SYCTF autonomous solve engine (Phase 1).

Public entrypoint: ``Engine().solve(target)``. The engine ingests a target
(file, directory, text blob, URL, or host), runs a grounded deterministic pass,
then an optional verified AI reasoning pass, and returns a :class:`SolveResult`.
"""

from __future__ import annotations

import re
from pathlib import Path

from syctf.engine.context import SolveContext
from syctf.engine.playbooks import detect_category
from syctf.engine.reasoner import Reasoner, SolveResult

__all__ = ["Engine", "SolveContext", "SolveResult"]

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
# Only treat as a host when it looks like an IP, a dotted domain, or host:port.
# A bare alphanumeric token (e.g. base64 ciphertext) is text, not a host.
_HOST_RE = re.compile(
    r"^(?:"
    r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?"          # IPv4 [:port]
    r"|[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?"      # domain.tld [:port]
    r"|[a-z0-9-]+:\d+"                             # host:port
    r")$",
    re.IGNORECASE,
)
_MAX_FILES = 25


class Engine:
    """High-level facade wiring ingestion, reasoning, and verification."""

    def __init__(self, *, router=None, verifier=None, detector=None, use_ai: bool = True) -> None:
        self.use_ai = use_ai
        self._detector = detector
        self._router = router
        self._verifier = verifier

    # -- lazy AI wiring -----------------------------------------------------
    def _ensure_ai(self):
        if not self.use_ai:
            return None, None
        if self._router is None:
            from syctf.ai.router import ModelRouter

            self._router = ModelRouter()
        if self._verifier is None:
            from syctf.ai.verifier import Verifier

            self._verifier = Verifier(detector=self._detector)
        return self._router, self._verifier

    # -- ingestion ----------------------------------------------------------
    def ingest(self, target: str, *, flag_format: str | None = None, budget: int = 12) -> SolveContext:
        ctx = SolveContext(target=target, flag_format=flag_format, budget=budget)
        if flag_format:
            from syctf.flags.detector import FlagDetector

            self._detector = FlagDetector(custom_format=flag_format)

        path = Path(target).expanduser()
        if path.exists():
            if path.is_dir():
                ctx.kind = "dir"
                ctx.files = sorted(p for p in path.rglob("*") if p.is_file())[:_MAX_FILES]
            else:
                ctx.kind = "file"
                ctx.files = [path]
        elif _URL_RE.match(target):
            ctx.kind = "url"
        elif _HOST_RE.match(target.strip()):
            ctx.kind = "host"
        else:
            ctx.kind = "text"

        file_type = None
        first = ctx.files[0] if ctx.files else None
        if first is not None:
            from syctf.engine.collectors import identify_file

            file_type, _ = identify_file(first)
        ctx.category = detect_category(
            kind=ctx.kind, file_type=file_type, path=first,
            text=target if ctx.kind == "text" else "",
        )
        return ctx

    # -- solve --------------------------------------------------------------
    def solve(
        self,
        target: str,
        *,
        flag_format: str | None = None,
        budget: int = 12,
        use_ai: bool | None = None,
        ensemble: int = 1,
    ) -> SolveResult:
        """Run the full autonomous pipeline against ``target``."""

        want_ai = self.use_ai if use_ai is None else use_ai
        ctx = self.ingest(target, flag_format=flag_format, budget=budget)
        router = verifier = None
        if want_ai:
            router, verifier = self._ensure_ai()
        reasoner = Reasoner(router=router, verifier=verifier, detector=self._detector)
        return reasoner.solve(ctx, use_ai=want_ai, ensemble=ensemble)

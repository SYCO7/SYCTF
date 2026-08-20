"""Git repository forensics: recover secrets from history, reflog, and dangling
objects (rebased-away / deleted commits).

Pure stdlib (zlib) — decompresses loose git objects directly, so it works on a
bare `.git` folder with no git binary. Perfect for "I rebased and forgot"
style challenges where the flag lives in an orphaned commit.
"""

from __future__ import annotations

import argparse
import zlib
from pathlib import Path

from rich.table import Table

from syctf.core.types import ExecutionContext
from syctf.flags.detector import FlagDetector
from syctf.utils.secrets import scan_secrets


def _find_git_dir(path: Path) -> Path | None:
    if path.name == ".git" and path.is_dir():
        return path
    if (path / ".git").is_dir():
        return path / ".git"
    if (path / "objects").is_dir() and (path / "HEAD").exists():
        return path
    return None


def read_loose_object(blob: bytes) -> tuple[str, bytes]:
    """Return (type, content) for a zlib-compressed loose git object."""

    raw = zlib.decompress(blob)
    header, _, content = raw.partition(b"\x00")
    typ = header.split(b" ", 1)[0].decode("ascii", "ignore")
    return typ, content


def iter_loose_objects(git_dir: Path):
    """Yield (sha, type, content) for every loose object."""

    objects = git_dir / "objects"
    for sub in sorted(objects.glob("[0-9a-f][0-9a-f]")):
        if not sub.is_dir():
            continue
        for obj in sorted(sub.iterdir()):
            sha = sub.name + obj.name
            try:
                typ, content = read_loose_object(obj.read_bytes())
                yield sha, typ, content
            except (OSError, zlib.error):
                continue


def read_reflog(git_dir: Path) -> list[str]:
    log = git_dir / "logs" / "HEAD"
    if not log.exists():
        return []
    try:
        return [ln for ln in log.read_text(errors="ignore").splitlines() if ln.strip()]
    except OSError:
        return []


class GitForensicsPlugin:
    """Mine a .git repo for flags and secrets in dangling/old commits."""

    name = "git-forensics"
    description = "Recover flags/secrets from git history, reflog, and dangling objects"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--path", required=True, help="Repo dir or .git dir")

    def run(self, args: argparse.Namespace, context: ExecutionContext) -> int:
        git_dir = _find_git_dir(Path(args.path).expanduser())
        if git_dir is None:
            context.console.print("[bold red]No .git repository found at that path.[/bold red]")
            return 2

        context.logger.info("forensics git-forensics dir=%s", git_dir)
        detector = FlagDetector(custom_format=context.cache.get("flag_format"))

        reflog = read_reflog(git_dir)
        if (git_dir / "objects" / "pack").exists() and any((git_dir / "objects" / "pack").glob("*.pack")):
            context.console.print("[yellow]Note: packed objects present — this reads loose objects only.[/yellow]")

        commits = 0
        blobs = 0
        flags: set[str] = set()
        secret_rows: list[tuple[str, str, str]] = []
        commit_rows: list[tuple[str, str]] = []

        for sha, typ, content in iter_loose_objects(git_dir):
            text = content.decode("latin-1", "ignore")
            for hit in detector.scan(text):
                if hit.real:
                    flags.add(hit.value)
            if typ == "commit":
                commits += 1
                msg = text.split("\n\n", 1)[1].strip() if "\n\n" in text else text.strip()
                commit_rows.append((sha[:10], msg.splitlines()[0][:70] if msg else "(no message)"))
            elif typ == "blob":
                blobs += 1
                for s in scan_secrets(text, source=f"blob {sha[:8]}"):
                    secret_rows.append((s.kind, s.value, s.context))

        context.console.print(f"[bold]git objects:[/bold] {commits} commits, {blobs} blobs, {len(reflog)} reflog entries")

        if reflog:
            table = Table(title="Reflog (rebased-away / moved refs live here)")
            table.add_column("old→new", style="cyan", no_wrap=True)
            table.add_column("action / message", style="white")
            for line in reflog[-15:]:
                left, _, msg = line.partition("\t")
                parts = left.split()
                oldnew = f"{parts[0][:8]}→{parts[1][:8]}" if len(parts) >= 2 else left[:18]
                table.add_row(oldnew, msg[:70])
            context.console.print(table)

        if commit_rows:
            ct = Table(title=f"Commits ({len(commit_rows)})")
            ct.add_column("sha", style="cyan", no_wrap=True)
            ct.add_column("message", style="white")
            for sha, msg in commit_rows[:25]:
                ct.add_row(sha, msg)
            context.console.print(ct)

        if secret_rows:
            st = Table(title=f"Secrets in blobs ({len(secret_rows)})")
            st.add_column("kind", style="red", no_wrap=True)
            st.add_column("value", style="yellow")
            st.add_column("object", style="dim")
            seen = set()
            for kind, val, ctx in secret_rows:
                if (kind, val) in seen:
                    continue
                seen.add((kind, val))
                st.add_row(kind, val, ctx)
            context.console.print(st)

        if flags:
            context.console.print("[bold green]Flags recovered from history:[/bold green]")
            for flag in sorted(flags):
                context.console.print(f"  - {flag}")
            context.cache["flag"] = sorted(flags)[0]
        else:
            context.console.print("[dim]No flag in loose objects — inspect the reflog SHAs above with `git show <sha>`.[/dim]")
        return 0


plugin = GitForensicsPlugin()

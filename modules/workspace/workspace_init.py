"""Challenge workspace initializer for fast CTF setup."""

from __future__ import annotations

import argparse
from typing import Any

from syctf.core.workspace_state import (
    sanitize_challenge_name,
    set_active_workspace,
    workspace_root_for,
)

name = "init"
description = "Initialize challenge workspace scaffold"

SUBDIRS = ["binary", "exploit", "decoded", "notes", "scripts"]


class WorkspaceInitPlugin:
    """Create reproducible challenge workspace layout."""

    name = name
    description = description

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register workspace init arguments."""

        parser.add_argument("name", help="Workspace/challenge directory name")

    def run(self, args: argparse.Namespace, context: Any) -> int:
        """Create workspace structure and seed notes/scripts."""

        challenge_name = sanitize_challenge_name(str(args.name))
        root = workspace_root_for(challenge_name)

        existed = root.exists()
        root.mkdir(parents=True, exist_ok=True)
        for folder in SUBDIRS:
            (root / folder).mkdir(parents=True, exist_ok=True)

        notes = root / "notes" / "notes.md"
        if not notes.exists():
            notes.write_text(
                "# Challenge Notes\n\n"
                "## Recon\n-\n\n"
                "## Hypotheses\n-\n\n"
                "## Payloads\n-\n\n"
                "## Flags / Artifacts\n-\n",
                encoding="utf-8",
            )

        helper = root / "scripts" / "run_local.sh"
        if not helper.exists():
            helper.write_text(
                "#!/usr/bin/env bash\nset -euo pipefail\n# Add quick test commands here\n",
                encoding="utf-8",
            )

        if existed:
            context.console.print(f"[yellow]Workspace already exists:[/yellow] {root}")

        set_active_workspace(root)
        context.cache["workspace_root"] = str(root)
        context.console.print(f"[bold green]Active workspace:[/bold green] {root}")
        context.console.print("[cyan]Structure:[/cyan] binary/, exploit/, decoded/, notes/, scripts/")
        return 0


plugin = WorkspaceInitPlugin()

"""Workspace target tracking plugin."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from syctf.core.workspace_state import active_workspace_path, set_target_path

name = "set-target"
description = "Set active target binary path for current workspace"


class WorkspaceSetTargetPlugin:
    """Persist target binary path for automation modules."""

    name = name
    description = description

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Register set-target command arguments."""

        parser.add_argument("target", help="Target binary path (absolute or relative)")

    def run(self, args: argparse.Namespace, context: Any) -> int:
        """Persist target path globally and in runtime cache."""

        raw = str(args.target).strip()
        if not raw:
            raise ValueError("Target path is required")

        workspace_root = None
        ws_raw = str(context.cache.get("workspace_root", "")).strip()
        if ws_raw:
            workspace_root = Path(ws_raw).expanduser().resolve()
        else:
            workspace_root = active_workspace_path()

        state = set_target_path(raw, workspace_root=workspace_root)
        target = str(state.get("target", "")).strip()
        context.cache["target"] = target
        context.console.print(f"[green]Workspace target set:[/green] {target}")
        return 0


plugin = WorkspaceSetTargetPlugin()

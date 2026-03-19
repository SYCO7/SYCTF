"""Persistent workspace state management for SYCTF."""

from __future__ import annotations

import json
import re
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from syctf.core.paths import get_workspaces_dir

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_STATE_FILE = ".workspace_state.json"


def sanitize_challenge_name(name: str) -> str:
    """Validate and sanitize workspace challenge name."""

    candidate = str(name).strip()
    if not candidate:
        raise ValueError("Challenge name cannot be empty")
    if "/" in candidate or "\\" in candidate or ".." in candidate:
        raise ValueError("Invalid challenge name: path traversal is not allowed")
    if not _NAME_RE.fullmatch(candidate):
        raise ValueError("Invalid challenge name: use letters, numbers, dot, underscore, hyphen")
    return candidate


def workspace_root_for(name: str) -> Path:
    """Return canonical workspace path for challenge name."""

    safe = sanitize_challenge_name(name)
    root = (get_workspaces_dir() / safe).resolve()
    base = get_workspaces_dir().resolve()
    if base not in root.parents:
        raise ValueError("Resolved workspace path escaped base directory")
    return root


def _state_path() -> Path:
    """Return state file path under ~/.syctf/workspaces/."""

    return get_workspaces_dir() / _STATE_FILE


def load_state() -> dict[str, Any]:
    """Load persistent workspace state."""

    path = _state_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def save_state(state: dict[str, Any]) -> None:
    """Persist workspace state atomically."""

    path = _state_path()
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def set_active_workspace(workspace_root: Path) -> dict[str, Any]:
    """Set active workspace globally and return updated state."""

    root = workspace_root.expanduser().resolve()
    state = load_state()
    state["active_workspace"] = str(root)
    state["updated_at"] = datetime.now(UTC).isoformat()
    save_state(state)
    return state


def set_target_path(target_path: str, workspace_root: Path | None = None) -> dict[str, Any]:
    """Set target binary path globally and return updated state."""

    raw_target = str(target_path).strip()
    if not raw_target:
        raise ValueError("Target path is required")

    candidate = Path(raw_target).expanduser()
    root: Path | None = None
    if workspace_root is not None:
        root = workspace_root.expanduser().resolve()

    if not candidate.is_absolute() and root is not None:
        candidate = (root / candidate).resolve()
        if candidate != root and root not in candidate.parents:
            raise ValueError("Relative target path escaped active workspace")
    else:
        candidate = candidate.resolve()

    if not candidate.exists() or not candidate.is_file():
        raise ValueError(f"Target path does not exist or is not a file: {candidate}")

    state = load_state()
    state["target"] = str(candidate)
    state["updated_at"] = datetime.now(UTC).isoformat()
    save_state(state)
    return state


def active_workspace_path() -> Path | None:
    """Return active workspace path if configured and existing."""

    raw = str(load_state().get("active_workspace", "")).strip()
    if not raw:
        return None
    path = Path(raw).expanduser().resolve()
    if not path.exists() or not path.is_dir():
        return None
    return path


def apply_state_to_cache(cache: dict[str, Any]) -> None:
    """Populate runtime cache from persisted workspace state."""

    state = load_state()
    active = str(state.get("active_workspace", "")).strip()
    if active:
        path = Path(active).expanduser().resolve()
        if path.exists() and path.is_dir():
            cache["workspace_root"] = str(path)

    target = str(state.get("target", "")).strip()
    if target:
        cache["target"] = target


def workspace_output_dir(kind: str, cache: dict[str, Any]) -> Path | None:
    """Resolve and ensure output subdirectory in active workspace."""

    raw = str(cache.get("workspace_root", "")).strip()
    if not raw:
        active = active_workspace_path()
        if active is None:
            return None
        raw = str(active)

    root = Path(raw).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return None

    out = (root / kind).resolve()
    if root not in out.parents and out != root:
        return None
    out.mkdir(parents=True, exist_ok=True)
    return out


def append_ai_note(cache: dict[str, Any], title: str, content: str) -> None:
    """Append AI interaction note into active workspace notes/ folder."""

    notes_dir = workspace_output_dir("notes", cache)
    if notes_dir is None:
        return

    note_file = notes_dir / "ai_notes.md"
    stamp = datetime.now(UTC).isoformat()
    body = (
        f"## {title}\n"
        f"- utc: {stamp}\n\n"
        f"```text\n{content.strip()}\n```\n\n"
    )
    with note_file.open("a", encoding="utf-8") as handle:
        handle.write(body)

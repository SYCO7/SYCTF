"""Runtime path helpers for user-scoped SYCTF directories."""

from __future__ import annotations

import os
from pathlib import Path


def get_syctf_home() -> Path:
    """Return ~/.syctf path and ensure it exists."""

    root = Path.home() / ".syctf"
    root.mkdir(parents=True, exist_ok=True)
    return root


def get_logs_dir() -> Path:
    """Return ~/.syctf/logs and ensure it exists."""

    logs_dir = get_syctf_home() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir


def get_config_dir() -> Path:
    """Return user config directory for SYCTF and ensure it exists."""

    xdg_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_home:
        base = Path(xdg_home)
    else:
        base = Path.home() / ".config"

    config_dir = base / "syctf"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_config_file_path() -> Path:
    """Return canonical user config file path."""

    return get_config_dir() / "config.json"


def get_plugins_dir() -> Path:
    """Return ~/.syctf/plugins and ensure it exists."""

    plugins_dir = get_syctf_home() / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    return plugins_dir


def get_workspaces_dir() -> Path:
    """Return ~/.syctf/workspaces and ensure it exists."""

    workspaces_dir = get_syctf_home() / "workspaces"
    workspaces_dir.mkdir(parents=True, exist_ok=True)
    return workspaces_dir


def get_cache_dir() -> Path:
    """Return ~/.syctf/cache and ensure it exists."""

    cache_dir = get_syctf_home() / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir

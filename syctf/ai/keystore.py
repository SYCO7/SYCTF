"""Menu-managed API key store (gitignored, user-scoped, chmod 600).

Keys set through the menu land in ~/.config/syctf/keys.json — never in the repo.
The provider factory checks environment variables first, then this store, so
`export XXX_API_KEY=...` still wins if present.
"""

from __future__ import annotations

import json
import os
import stat

from syctf.core.paths import get_config_dir


def _path():
    return get_config_dir() / "keys.json"


def load_keys() -> dict[str, str]:
    path = _path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def set_key(provider: str, key: str) -> None:
    """Store (or clear, if empty) a provider's API key with 0600 perms."""

    keys = load_keys()
    provider = provider.strip().lower()
    if key.strip():
        keys[provider] = key.strip()
    else:
        keys.pop(provider, None)
    path = _path()
    path.write_text(json.dumps(keys, indent=2), encoding="utf-8")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass


def get_key(provider: str) -> str | None:
    return load_keys().get(provider.strip().lower())

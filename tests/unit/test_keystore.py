"""API keystore + env precedence + menu-driven RSA decrypt."""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess

import pytest
from rich.console import Console

from syctf.core.types import AppConfig, ExecutionContext


def _ctx() -> ExecutionContext:
    return ExecutionContext(config=AppConfig(), logger=logging.getLogger("t"),
                            console=Console(), plugin_loader=None, cache={})


def test_keystore_roundtrip_and_env_precedence(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    from syctf.ai.keystore import get_key, set_key

    set_key("nvidia", "nvapi-abc")
    assert get_key("nvidia") == "nvapi-abc"

    from syctf.ai.providers import build_provider, resolve_api_key
    from syctf.ai.providers.catalog import get_spec

    assert build_provider("nvidia").api_key == "nvapi-abc"          # from keystore
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-env")
    assert resolve_api_key(get_spec("nvidia")) == "nvapi-env"        # env wins

    set_key("nvidia", "")                                            # clear
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    assert get_key("nvidia") is None


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_rsa_decrypt_module(tmp_path):
    import syctf.modules.crypto.rsa_decrypt as m

    priv, pub, ct = tmp_path / "p.pem", tmp_path / "pub.pem", tmp_path / "c.bin"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(priv)], check=True, capture_output=True)
    subprocess.run(["openssl", "rsa", "-in", str(priv), "-pubout", "-out", str(pub)],
                   check=True, capture_output=True)
    enc = subprocess.run(["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", str(pub),
                          "-pkeyopt", "rsa_padding_mode:pkcs1"], input=b"flag{rsa_menu}", capture_output=True)
    ct.write_bytes(enc.stdout)

    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(key=str(priv), file=str(ct), padding="auto"), ctx)
    assert rc == 0
    assert ctx.cache.get("flag") == "flag{rsa_menu}"

"""Mobile (APK) module tests — offline, synthetic APK."""

from __future__ import annotations

import argparse
import logging
import zipfile
from pathlib import Path

from rich.console import Console

from syctf.core.plugin_loader import PluginLoader
from syctf.core.types import AppConfig, ExecutionContext

MODULES_ROOT = Path(__file__).resolve().parents[2] / "syctf" / "modules"


def _ctx() -> ExecutionContext:
    return ExecutionContext(
        config=AppConfig(),
        logger=logging.getLogger("test.mobile"),
        console=Console(),
        plugin_loader=None,
        cache={},
    )


def _make_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest package='com.x'/>")  # not real AXML on purpose
        zf.writestr("res/values/strings.xml", "<resources>AKIAIOSFODNN7EXAMPLE https://api.example.com/v1</resources>")
        zf.writestr("classes.dex", b"junk...flag{apk_reversed}...javax/crypto/Cipher...Runtime.exec")
    return path


def test_loader_discovers_mobile_modules():
    loader = PluginLoader(modules_roots=[MODULES_ROOT], logger=logging.getLogger("l"))
    found = loader.discover("mobile")
    assert {"apk-info", "apk-secrets", "dex-strings"} <= set(found)


def test_apk_info_graceful_on_bad_manifest(tmp_path):
    apk = _make_apk(tmp_path / "app.apk")
    import syctf.modules.mobile.apk_info as m

    rc = m.plugin.run(argparse.Namespace(file=str(apk)), _ctx())
    assert rc == 0  # degrades gracefully when manifest is not valid AXML


def test_apk_secrets_finds_key(tmp_path):
    apk = _make_apk(tmp_path / "app.apk")
    import syctf.modules.mobile.apk_secrets as m

    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(file=str(apk), max_urls=10), ctx)
    assert rc == 0
    kinds = {k for k, _ in ctx.cache.get("apk_secrets", [])}
    assert "AWS Access Key ID" in kinds


def test_dex_strings_finds_flag(tmp_path):
    apk = _make_apk(tmp_path / "app.apk")
    import syctf.modules.mobile.dex_strings as m

    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(file=str(apk), min_len=5, grep=None), ctx)
    assert rc == 0
    assert ctx.cache.get("flag") == "flag{apk_reversed}"


def test_rejects_non_apk(tmp_path):
    bad = tmp_path / "x.txt"
    bad.write_text("not a zip")
    import syctf.modules.mobile.apk_info as m

    assert m.plugin.run(argparse.Namespace(file=str(bad)), _ctx()) == 2

"""Web analyzer tests: JWT attacks + probe detection logic (offline)."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import logging

from rich.console import Console

from syctf.core.types import AppConfig, ExecutionContext
from syctf.modules.web.jwt_tool import crack_hs256, decode_jwt, forge_alg_none
from syctf.modules.web.lfi_probe import passwd_signature
from syctf.modules.web.sqli_probe import error_signature
from syctf.modules.web.xss_probe import reflects_unescaped


def _ctx() -> ExecutionContext:
    return ExecutionContext(
        config=AppConfig(),
        logger=logging.getLogger("test.web"),
        console=Console(),
        plugin_loader=None,
        cache={},
    )


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _make_hs256(payload: dict, secret: str) -> str:
    header = _b64({"alg": "HS256", "typ": "JWT"})
    body = _b64(payload)
    sig = hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def test_jwt_decode_and_forge_none():
    token = _make_hs256({"user": "guest", "admin": False}, "secret")
    header, payload, _ = decode_jwt(token)
    assert payload["user"] == "guest"
    forged = forge_alg_none(header, payload)
    assert forged.endswith(".")
    fh, _, _ = decode_jwt(forged + "x")  # add dummy sig char to keep 3 parts
    assert fh["alg"] == "none"


def test_jwt_crack_hs256():
    token = _make_hs256({"admin": True}, "changeme")
    assert crack_hs256(token, ["nope", "changeme", "other"]) == "changeme"


def test_jwt_plugin_cracks_and_caches():
    import syctf.modules.web.jwt_tool as m

    token = _make_hs256({"role": "user"}, "password")
    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(token=token, wordlist=None, forge_none=False), ctx)
    assert rc == 0
    assert ctx.cache.get("jwt_secret") == "password"


def test_sqli_error_signature():
    assert error_signature("You have an error in your SQL syntax near ...")
    assert error_signature("Warning: mysql_fetch_array()")
    assert error_signature("ORA-00933: SQL command not properly ended")
    assert error_signature("nothing to see") is None


def test_xss_reflection_detection():
    payload = "<svg/onload=alert(1)>"
    assert reflects_unescaped(f"<html>{payload}</html>", payload) is True
    escaped = "&lt;svg/onload=alert(1)&gt;"
    assert reflects_unescaped(f"<html>{escaped}</html>", payload) is False


def test_lfi_passwd_signature():
    assert passwd_signature("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
    assert passwd_signature("nope") is False

"""Secret-pattern scanner tests."""

from __future__ import annotations

from syctf.utils.axml import AxmlError, parse_axml
from syctf.utils.secrets import scan_secrets


def test_finds_aws_and_google_keys():
    text = "id=AKIAIOSFODNN7EXAMPLE key=AIza" + "b" * 35
    kinds = {h.kind for h in scan_secrets(text)}
    assert "AWS Access Key ID" in kinds
    assert "Google API Key" in kinds


def test_finds_private_key_and_jwt():
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n"
        "tok=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdEFGHijklMNOP"
    )
    kinds = {h.kind for h in scan_secrets(text)}
    assert "Private Key Block" in kinds
    assert "JWT" in kinds


def test_generic_assignment_entropy_gate():
    # Low-entropy repeated value is ignored; a random-looking one is caught.
    assert not any(h.kind == "Generic Secret Assignment" for h in scan_secrets('password="aaaaaaaa"'))
    assert any(h.kind == "Generic Secret Assignment" for h in scan_secrets('api_key="G7x-Qz9_Pk2Lm4Rt8Wv"'))


def test_axml_rejects_non_axml():
    try:
        parse_axml(b"<manifest package='x'/>")
    except AxmlError:
        return
    raise AssertionError("expected AxmlError on text input")

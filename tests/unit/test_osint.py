"""OSINT module tests (offline; network monkeypatched)."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from rich.console import Console

from syctf.core.plugin_loader import PluginLoader
from syctf.core.types import AppConfig, ExecutionContext
from syctf.utils.net_utils import valid_domain

MODULES_ROOT = Path(__file__).resolve().parents[2] / "syctf" / "modules"


def _ctx() -> ExecutionContext:
    return ExecutionContext(
        config=AppConfig(),
        logger=logging.getLogger("test.osint"),
        console=Console(),
        plugin_loader=None,
        cache={},
    )


def test_valid_domain_accepts_and_normalizes():
    assert valid_domain("Example.COM") == "example.com"
    assert valid_domain("https://sub.example.com/path?x=1") == "sub.example.com"
    assert valid_domain("user@mail.example.co.uk:443") == "mail.example.co.uk"


@pytest.mark.parametrize("bad", ["", "not a domain", "localhost", "http://", "a..b", "-x.com"])
def test_valid_domain_rejects(bad):
    with pytest.raises(ValueError):
        valid_domain(bad)


def test_loader_discovers_osint_modules():
    loader = PluginLoader(modules_roots=[MODULES_ROOT], logger=logging.getLogger("test.loader"))
    found = loader.discover("osint")
    assert {"subdomains", "dns-recon", "whois", "wayback", "username-enum"} <= set(found)


@pytest.mark.parametrize(
    "module_path",
    ["subdomains", "dns_recon", "whois_lookup", "wayback", "username_enum"],
)
def test_module_exposes_plugin_interface(module_path):
    import importlib

    mod = importlib.import_module(f"syctf.modules.osint.{module_path}")
    plugin = mod.plugin
    assert plugin.name and plugin.description
    assert callable(plugin.add_arguments) and callable(plugin.run)


def test_subdomains_parses_crtsh(monkeypatch):
    import syctf.modules.osint.subdomains as sub

    fake = [
        {"name_value": "www.example.com\n*.example.com"},
        {"name_value": "api.example.com"},
        {"name_value": "unrelated.other.org"},
    ]
    monkeypatch.setattr(sub, "http_json", lambda *a, **k: fake)

    import argparse

    args = argparse.Namespace(domain="example.com", limit=50)
    ctx = _ctx()
    rc = sub.plugin.run(args, ctx)
    assert rc == 0
    # "*.example.com" -> apex; www/api kept; unrelated.other.org dropped.
    assert set(ctx.cache["osint_subdomains"]) == {"example.com", "www.example.com", "api.example.com"}


def test_dns_recon_parses(monkeypatch):
    import argparse

    import syctf.modules.osint.dns_recon as dns

    def fake_json(url, params=None, timeout=None):
        if params and params.get("type") == "A":
            return {"Answer": [{"data": "93.184.216.34"}]}
        return {"Answer": []}

    monkeypatch.setattr(dns, "http_json", fake_json)
    rc = dns.plugin.run(argparse.Namespace(domain="example.com", types="A,MX"), _ctx())
    assert rc == 0

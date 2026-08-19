"""Cloud module tests — offline."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from rich.console import Console

from syctf.core.plugin_loader import PluginLoader
from syctf.core.types import AppConfig, ExecutionContext

MODULES_ROOT = Path(__file__).resolve().parents[2] / "syctf" / "modules"


def _ctx() -> ExecutionContext:
    return ExecutionContext(
        config=AppConfig(),
        logger=logging.getLogger("test.cloud"),
        console=Console(),
        plugin_loader=None,
        cache={},
    )


def test_loader_discovers_cloud_modules():
    loader = PluginLoader(modules_roots=[MODULES_ROOT], logger=logging.getLogger("l"))
    found = loader.discover("cloud")
    assert {"cloud-keys", "s3-enum", "imds-ssrf"} <= set(found)


def test_cloud_keys_text():
    import syctf.modules.cloud.cloud_keys as m

    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(path=None, text="key=AKIAIOSFODNN7EXAMPLE"), ctx)
    assert rc == 0
    kinds = {k for k, _ in ctx.cache.get("cloud_secrets", [])}
    assert "AWS Access Key ID" in kinds


def test_cloud_keys_dir(tmp_path):
    (tmp_path / "sa.json").write_text('{"type": "service_account", "project_id": "p"}')
    import syctf.modules.cloud.cloud_keys as m

    ctx = _ctx()
    rc = m.plugin.run(argparse.Namespace(path=str(tmp_path), text=None), ctx)
    assert rc == 0
    kinds = {k for k, _ in ctx.cache.get("cloud_secrets", [])}
    assert "GCP Service Account" in kinds


def test_s3_classify():
    import syctf.modules.cloud.s3_enum as m

    p = m.plugin
    assert "PUBLIC" in p._classify(200, "<ListBucketResult><Name>b</Name></ListBucketResult>")
    assert p._classify(403, "") == "exists (private)"
    assert p._classify(404, "NoSuchBucket") == "no bucket"


def test_imds_requires_fuzz():
    import syctf.modules.cloud.imds_ssrf as m

    assert m.plugin.run(argparse.Namespace(url="http://t/no-token", encode=False), _ctx()) == 2

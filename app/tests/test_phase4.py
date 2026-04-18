"""Tests for Phase 4 components — IPFS publish, SNS resolver, mirror health."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest


def _mock_response(method: str, url: str, status: int = 200, **kw) -> httpx.Response:
    """Build a Response with an attached Request so raise_for_status works."""
    req = httpx.Request(method, url)
    return httpx.Response(status, request=req, **kw)


# ══════════════════════════════════════════════════════════════════════════
# IPFS publish
# ══════════════════════════════════════════════════════════════════════════


def test_ipfs_publish_sends_files_and_parses_root_cid(tmp_path: Path):
    from vortex_controller.ipfs_publish import publish_to_ipfs

    src = tmp_path / "web"
    src.mkdir()
    (src / "index.html").write_text("<!doctype html><title>t</title>")
    (src / "style.css").write_text(".a{}")
    (src / "sub").mkdir()
    (src / "sub" / "app.js").write_text("console.log(1)")

    # Simulated kubo /api/v0/add NDJSON response
    fake_response_lines = [
        {"Name": "index.html", "Hash": "bafy-index", "Size": "30"},
        {"Name": "style.css",  "Hash": "bafy-style", "Size": "4"},
        {"Name": "sub/app.js", "Hash": "bafy-app",   "Size": "14"},
        {"Name": "",           "Hash": "bafy-root",  "Size": "48"},
    ]
    fake_body = "\n".join(json.dumps(x) for x in fake_response_lines)

    def fake_post(*args, **kwargs):
        files = kwargs.get("files") or []
        assert len(files) == 3, f"expected 3 files, got {len(files)}"
        return _mock_response("POST", "http://127.0.0.1:5001/api/v0/add", text=fake_body)

    with patch.object(httpx.Client, "post", side_effect=fake_post):
        result = publish_to_ipfs(src_dir=src, api_url="http://127.0.0.1:5001")

    assert result["root_cid"] == "bafy-root"
    assert len(result["files"]) == 3
    names = sorted(f["name"] for f in result["files"])
    assert names == ["index.html", "style.css", "sub/app.js"]


def test_ipfs_publish_errors_on_empty_dir(tmp_path: Path):
    from vortex_controller.ipfs_publish import publish_to_ipfs

    with pytest.raises(RuntimeError, match="no files"):
        publish_to_ipfs(src_dir=tmp_path, api_url="http://127.0.0.1:5001")


# ══════════════════════════════════════════════════════════════════════════
# SNS resolver
# ══════════════════════════════════════════════════════════════════════════


def test_sns_domain_validation():
    from app.peer.sns_resolver import is_sol_domain

    assert is_sol_domain("vortexx.sol")
    assert is_sol_domain("Vortexx.SOL")
    assert is_sol_domain("sub.vortexx.sol")
    assert not is_sol_domain("")
    assert not is_sol_domain("vortexx.com")
    assert not is_sol_domain(".sol")
    assert not is_sol_domain("vortexx")


@pytest.mark.asyncio
async def test_sns_resolve_returns_url_and_txt_metadata():
    from app.peer.sns_resolver import resolve

    # Fake Bonfida responses: the client makes two GETs in parallel
    def fake_get(url, *args, **kwargs):
        surl = str(url)
        if "/URL" in surl:
            return _mock_response("GET", surl, json={"result": {"content": "vortexx.example"}})
        if "/TXT" in surl:
            return _mock_response("GET", surl, json={
                "result": {"content": "pubkey=ff11;mirrors=ipfs://bafy,http://x.onion"}
            })
        return _mock_response("GET", surl, status=404)

    with patch.object(httpx.AsyncClient, "get", side_effect=fake_get):
        rec = await resolve("vortexx.sol")

    assert rec.is_resolved
    assert rec.url == "https://vortexx.example"  # normalised
    assert rec.pubkey == "ff11"
    assert rec.mirrors == ["ipfs://bafy", "http://x.onion"]


@pytest.mark.asyncio
async def test_sns_resolve_handles_network_failure_gracefully():
    from app.peer.sns_resolver import resolve

    def explode(*args, **kwargs):
        raise httpx.ConnectError("no network")

    with patch.object(httpx.AsyncClient, "get", side_effect=explode):
        rec = await resolve("vortexx.sol")

    assert not rec.is_resolved  # no URL returned, but no exception
    assert rec.url is None


@pytest.mark.asyncio
async def test_sns_resolve_rejects_non_sol_domain():
    from app.peer.sns_resolver import resolve

    with pytest.raises(ValueError):
        await resolve("vortexx.com")


# ══════════════════════════════════════════════════════════════════════════
# Mirror health
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_mirror_health_probes_each_url_and_records_status():
    from vortex_controller.mirror_health import MirrorHealthChecker

    urls = [
        "https://ok.example",
        "https://dead.example",
        "ipfs://bafygoodcid",
        "http://abc.onion",            # skipped without tor proxy
    ]

    async def fake_head(self, url, **kwargs):
        if "dead" in url:
            raise httpx.ConnectError("dead")
        if "ok.example" in url or "ipfs.io" in url:
            return _mock_response("HEAD", url)
        raise httpx.ConnectError("unknown target " + url)

    checker = MirrorHealthChecker(urls=urls)

    with patch.object(httpx.AsyncClient, "head", fake_head):
        await checker._sweep()

    s = checker.state.by_url
    assert s["https://ok.example"].ok is True
    assert s["https://ok.example"].latency_ms is not None

    assert s["https://dead.example"].ok is False
    assert "ConnectError" in (s["https://dead.example"].error or "")

    # IPFS is probed via the public gateway
    assert s["ipfs://bafygoodcid"].ok is True

    # Onion without proxy → skipped with diagnostic
    assert s["http://abc.onion"].ok is False
    assert "tor" in (s["http://abc.onion"].error or "").lower()


@pytest.mark.asyncio
async def test_mirror_health_snapshot_shape():
    from vortex_controller.mirror_health import MirrorHealthChecker

    checker = MirrorHealthChecker(urls=["https://ok.example"])

    async def fake_head(self, url, **kwargs):
        return _mock_response("HEAD", url)

    with patch.object(httpx.AsyncClient, "head", fake_head):
        await checker._sweep()

    snap = checker.state.snapshot()
    assert isinstance(snap["last_sweep"], int)
    assert snap["last_sweep"] > 0
    assert len(snap["mirrors"]) == 1
    m = snap["mirrors"][0]
    assert m["url"] == "https://ok.example"
    assert m["ok"] is True
    assert isinstance(m["latency_ms"], int)
    assert isinstance(m["last_checked"], int)


# ══════════════════════════════════════════════════════════════════════════
# Controller integration: /v1/mirrors now includes health
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_mirrors_endpoint_exposes_health_after_sweep():
    from asgi_lifespan import LifespanManager
    from vortex_controller.main import create_app
    from app.peer.controller_client import verify_controller_signature

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)

        # Patch HEAD so the startup sweep resolves without hitting the network.
        async def fake_head(self, url, **kwargs):
            if "dead" in url:
                raise httpx.ConnectError("dead")
            return _mock_response("HEAD", url)

        app = create_app(
            keys_dir=d / "ck",
            auto_approve=True,
            entry_urls=["wss://entry.example"],
            mirror_urls=[
                "https://alive.example",
                "https://dead.example",
                "ipfs://bafysometest",
            ],
            db_url=f"sqlite+aiosqlite:///{d}/c.db",
        )

        with patch.object(httpx.AsyncClient, "head", fake_head):
            async with LifespanManager(app):
                from httpx import AsyncClient, ASGITransport
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://ctrl",
                ) as http:
                    r = await http.get("/v1/health")
                    ctrl_pub = r.json()["pubkey"]

                    r = await http.get("/v1/mirrors")
                    env = r.json()

                mirrors = env["payload"]["mirrors"]
                by_url = {m["url"]: m for m in mirrors}

                assert by_url["https://alive.example"]["healthy"] is True
                assert by_url["https://dead.example"]["healthy"] is False
                assert "dead" in by_url["https://dead.example"]["error"].lower()
                # Signature still valid
                assert verify_controller_signature(env["payload"], env["signature"], ctrl_pub)

                # Unsigned health shortcut also works
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://ctrl",
                ) as http:
                    r = await http.get("/v1/mirrors/health")
                    snap = r.json()
                    assert len(snap["mirrors"]) == 3

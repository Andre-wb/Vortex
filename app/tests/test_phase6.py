"""Tests for Phase 6 — never connect to unverified nodes.

Covers:
    - Controller integrity gate blocks all non-safe endpoints when tampered.
    - ControllerClient.ensure_verified_url() picks only verified URLs.
    - ControllerClient raises IntegrityRefusal when no URL verifies.
    - Handoff-accept on Vortex node returns 503 when overloaded.
    - MigrationPusher builds expected payload with only verified alternatives.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest


def _mock_response(method: str, url: str, status: int = 200, **kw) -> httpx.Response:
    req = httpx.Request(method, url)
    return httpx.Response(status, request=req, **kw)


# ══════════════════════════════════════════════════════════════════════════
# 1. Integrity gate on controller
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_integrity_gate_blocks_protected_endpoints_on_tampered():
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport

    from vortex_controller.integrity.verify import IntegrityReport
    from vortex_controller.integrity_gate import IntegrityGateMiddleware

    # Minimal app with a fake "tampered" state
    app = FastAPI()
    app.state.integrity = IntegrityReport(
        status="tampered",
        message="1 file modified",
        signed_by="ff" * 32,
    )

    @app.get("/v1/health")
    async def _health(): return {"status": "ok"}
    @app.get("/v1/integrity")
    async def _integrity(): return {"status": "tampered"}
    @app.get("/v1/nodes/random")
    async def _nodes(): return {"nodes": []}
    @app.get("/v1/entries")
    async def _entries(): return {"entries": []}
    @app.get("/")
    async def _root(): return {"page": "ok"}

    app.add_middleware(IntegrityGateMiddleware)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://x") as http:
        # Safe endpoints: still open
        assert (await http.get("/v1/health")).status_code == 200
        assert (await http.get("/v1/integrity")).status_code == 200
        assert (await http.get("/")).status_code == 200

        # Protected endpoints: blocked
        r = await http.get("/v1/nodes/random")
        assert r.status_code == 503
        body = r.json()
        assert body["error"] == "integrity_failed"
        assert body["status"] == "tampered"

        r = await http.get("/v1/entries")
        assert r.status_code == 503


@pytest.mark.asyncio
async def test_integrity_gate_passes_when_verified():
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport

    from vortex_controller.integrity.verify import IntegrityReport
    from vortex_controller.integrity_gate import IntegrityGateMiddleware

    app = FastAPI()
    app.state.integrity = IntegrityReport(
        status="verified", message="ok", matched=10,
    )

    @app.get("/v1/nodes/random")
    async def _nodes(): return {"nodes": ["x"]}

    app.add_middleware(IntegrityGateMiddleware)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://x") as http:
        r = await http.get("/v1/nodes/random")
        assert r.status_code == 200
        assert r.json() == {"nodes": ["x"]}


@pytest.mark.asyncio
async def test_integrity_gate_passes_when_no_manifest():
    """Dev builds (no INTEGRITY.sig.json) still serve traffic — just warn."""
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport

    from vortex_controller.integrity.verify import IntegrityReport
    from vortex_controller.integrity_gate import IntegrityGateMiddleware

    app = FastAPI()
    app.state.integrity = IntegrityReport(status="no_manifest", message="dev")
    @app.get("/v1/nodes/random")
    async def _nodes(): return {"nodes": []}
    app.add_middleware(IntegrityGateMiddleware)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://x") as http:
        assert (await http.get("/v1/nodes/random")).status_code == 200


# ══════════════════════════════════════════════════════════════════════════
# 2. ControllerClient verify-first behavior
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_controller_client_picks_first_verified_url():
    from app.peer.controller_client import ControllerClient, NodeSigningKey

    # Fake /v1/integrity responses keyed by hostname
    scenarios = {
        "bad1": {"status": "tampered", "signed_by": "aa" * 32, "message": "modified"},
        "bad2": {"status": "bad_signature", "signed_by": "bb" * 32, "message": "broken"},
        "good": {"status": "verified", "signed_by": "cc" * 32, "message": "ok"},
    }

    async def fake_get(self, url, **kw):
        for name, data in scenarios.items():
            if name in str(url):
                return _mock_response("GET", str(url), json=data)
        return _mock_response("GET", str(url), status=503)

    with tempfile.TemporaryDirectory() as d:
        sk = NodeSigningKey.load_or_create(Path(d))
        client = ControllerClient(
            url="http://bad1.example",
            controller_pubkey="deadbeef",
            signing_key=sk,
            announce_endpoints=["wss://me:9000"],
            fallback_urls=["http://bad2.example", "http://good.example"],
            expected_release_pubkey="cc" * 32,
        )
        with patch.object(httpx.AsyncClient, "get", fake_get):
            chosen = await client.ensure_verified_url()
        assert chosen == "http://good.example"
        assert client.url == "http://good.example"


@pytest.mark.asyncio
async def test_controller_client_refuses_when_none_verified():
    from app.peer.controller_client import ControllerClient, NodeSigningKey, IntegrityRefusal

    async def fake_get(self, url, **kw):
        # Every candidate is tampered
        return _mock_response("GET", str(url), json={
            "status": "tampered", "signed_by": "ff" * 32, "message": "bad",
        })

    with tempfile.TemporaryDirectory() as d:
        sk = NodeSigningKey.load_or_create(Path(d))
        client = ControllerClient(
            url="http://bad.example",
            controller_pubkey="deadbeef",
            signing_key=sk,
            announce_endpoints=["wss://me:9000"],
            fallback_urls=["http://also-bad.example"],
            expected_release_pubkey="aa" * 32,
        )
        with patch.object(httpx.AsyncClient, "get", fake_get):
            with pytest.raises(IntegrityRefusal):
                await client.ensure_verified_url()


@pytest.mark.asyncio
async def test_controller_client_rejects_wrong_release_key():
    """Verified status alone isn't enough — signed_by must match pin."""
    from app.peer.controller_client import ControllerClient, NodeSigningKey, IntegrityRefusal

    async def fake_get(self, url, **kw):
        return _mock_response("GET", str(url), json={
            "status": "verified", "signed_by": "11" * 32,
            "message": "verified but by impostor",
        })

    with tempfile.TemporaryDirectory() as d:
        sk = NodeSigningKey.load_or_create(Path(d))
        client = ControllerClient(
            url="http://impostor.example",
            controller_pubkey="deadbeef",
            signing_key=sk,
            announce_endpoints=["wss://me:9000"],
            expected_release_pubkey="99" * 32,  # pinning a different key
        )
        with patch.object(httpx.AsyncClient, "get", fake_get):
            with pytest.raises(IntegrityRefusal):
                await client.ensure_verified_url()


@pytest.mark.asyncio
async def test_controller_client_skips_release_key_check_when_unset():
    """Dev/self-hosted mode: no release_pubkey pinning → any verified works."""
    from app.peer.controller_client import ControllerClient, NodeSigningKey

    async def fake_get(self, url, **kw):
        return _mock_response("GET", str(url), json={
            "status": "verified", "signed_by": "42" * 32, "message": "ok",
        })

    with tempfile.TemporaryDirectory() as d:
        sk = NodeSigningKey.load_or_create(Path(d))
        client = ControllerClient(
            url="http://custom.example",
            controller_pubkey="deadbeef",
            signing_key=sk,
            announce_endpoints=["wss://me:9000"],
            expected_release_pubkey=None,
        )
        with patch.object(httpx.AsyncClient, "get", fake_get):
            chosen = await client.ensure_verified_url()
        assert chosen == "http://custom.example"


# ══════════════════════════════════════════════════════════════════════════
# 3. Vortex node load-gate on handoff
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_handoff_accept_refuses_when_overloaded():
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport

    from app.peer.controller_client import NodeSigningKey
    from app.session.migration import router as session_router, _load, _resolver
    from app.session.handoff_token import _reset_replay_cache_for_tests

    _reset_replay_cache_for_tests()

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        self_key = NodeSigningKey.load_or_create(d / "self")

        app = FastAPI()
        app.state.signing_key = self_key
        app.include_router(session_router)

        # Build any valid token — the gate should reject before we even verify it
        from app.session.handoff_token import issue_handoff_token
        token = issue_handoff_token(
            signing_key=self_key,
            user_pubkey="aa" * 32,
            username="alice",
            rooms=[1],
        )

        async def fake_active_count():
            return _load.MAX_CONN  # 100% load

        with patch("app.session.migration._active_ws_count",
                   lambda: _load.MAX_CONN), \
             patch("app.session.migration._collect_alternatives",
                   return_value=[]):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://me") as http:
                r = await http.post("/api/session/handoff/accept", json={"token": token})
        assert r.status_code == 503
        body = r.json()
        assert body["detail"]["error"] == "overloaded"
        assert body["detail"]["load"] >= 0.85


@pytest.mark.asyncio
async def test_handoff_accept_passes_when_not_overloaded():
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport

    from app.peer.controller_client import NodeSigningKey
    from app.session.migration import router as session_router
    from app.session.handoff_token import (
        _reset_replay_cache_for_tests, issue_handoff_token,
    )

    _reset_replay_cache_for_tests()

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        src_key = NodeSigningKey.load_or_create(d / "src")
        tgt_key = NodeSigningKey.load_or_create(d / "tgt")

        app = FastAPI()
        app.state.signing_key = tgt_key
        app.include_router(session_router)

        token = issue_handoff_token(
            signing_key=src_key,
            user_pubkey="aa" * 32,
            username="alice",
            rooms=[1, 2],
        )

        # Resolver must trust src_key
        class _AlwaysTrust:
            async def warm(self): pass
            def __call__(self, pubkey_hex):
                return pubkey_hex.lower() == src_key.pubkey_hex().lower()

        with patch("app.session.migration._active_ws_count", lambda: 0), \
             patch("app.session.migration._resolver", _AlwaysTrust()):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://me") as http:
                r = await http.post("/api/session/handoff/accept", json={"token": token})
        assert r.status_code == 200


# ══════════════════════════════════════════════════════════════════════════
# 4. MigrationPusher payload shape
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_migration_pusher_includes_only_verified_alternatives():
    """The payload sent to clients should reuse the same _collect_alternatives
    source we already verified — tampered controllers never leak through."""
    from app.session import migration_pusher as mp
    from app.session.migration import MigrationHintAlt

    fake_alts = [
        MigrationHintAlt(
            pubkey="aa" * 32,
            endpoints=["wss://good-a:9000"],
            metadata={"name": "good-a"},
            last_seen=int(time.time()),
        ),
        MigrationHintAlt(
            pubkey="bb" * 32,
            endpoints=["wss://good-b:9000"],
            metadata={"name": "good-b"},
            last_seen=int(time.time()),
        ),
    ]

    pushed_payloads = []

    class _FakeManager:
        _rooms = {1: {100: object(), 101: object()}}
        async def send_to_user(self, room, user, payload):
            pushed_payloads.append((room, user, payload))
            return True

    class _FakeLoad:
        def snapshot(self): return {"load": 0.91, "accepts_new": False}
        def should_suggest_migration(self): return True

    class _FakeSigningKey:
        def pubkey_hex(self): return "cc" * 32

    # Run the tick logic directly
    with patch("app.session.migration._load", _FakeLoad()), \
         patch("app.session.migration._collect_alternatives",
               return_value=fake_alts), \
         patch("app.session.migration._require_signing_key",
               return_value=_FakeSigningKey()), \
         patch("app.peer.connection_manager.manager", _FakeManager()):
        pusher = mp.MigrationPusher()
        pusher._over_since = time.time() - 60   # past sustained threshold
        pusher._last_push = 0                   # cooldown not active
        await pusher._tick()

    assert len(pushed_payloads) == 2, pushed_payloads
    _, _, payload = pushed_payloads[0]
    assert payload["type"] == "migrate_suggest"
    assert payload["reason"] == "overload"
    assert payload["load"] == 0.91
    assert len(payload["targets"]) == 2
    sent_pubkeys = {t["pubkey"] for t in payload["targets"]}
    assert sent_pubkeys == {"aa" * 32, "bb" * 32}


@pytest.mark.asyncio
async def test_migration_pusher_skips_if_no_alternatives():
    """Never push an empty suggestion — clients would then disconnect into nothing."""
    from app.session import migration_pusher as mp

    pushed_payloads = []

    class _FakeManager:
        _rooms = {1: {100: object()}}
        async def send_to_user(self, r, u, p):
            pushed_payloads.append((r, u, p))
            return True

    class _FakeLoad:
        def snapshot(self): return {"load": 0.95, "accepts_new": False}
        def should_suggest_migration(self): return True

    class _FakeSigningKey:
        def pubkey_hex(self): return "cc" * 32

    with patch("app.session.migration._load", _FakeLoad()), \
         patch("app.session.migration._collect_alternatives", return_value=[]), \
         patch("app.session.migration._require_signing_key",
               return_value=_FakeSigningKey()), \
         patch("app.peer.connection_manager.manager", _FakeManager()):
        pusher = mp.MigrationPusher()
        pusher._over_since = time.time() - 60
        pusher._last_push = 0
        await pusher._tick()

    assert pushed_payloads == []

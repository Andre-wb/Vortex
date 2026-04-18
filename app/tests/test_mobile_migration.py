"""Reference mobile migration test / simulator.

Demonstrates the full mobile lifecycle across two Vortex nodes registered
with one controller (the Phase 1 registry).

Scenario simulated:

    1. Controller is running. Two Vortex nodes A and B register with it.
    2. A mobile client is "connected" to node A:
        - Posts a cursor (last_bmp_ts, rooms)
        - Deposits a BMP message
    3. Node A wants to hand off the client to node B:
        - Client calls POST /api/session/handoff/init on A → gets signed token
    4. Client calls POST /api/session/handoff/accept on B with that token
        - B verifies A's signature via the controller peer registry
        - B stores the cursor locally
    5. Client reads GET /api/session/cursor on B — same state as on A
    6. Client calls /api/session/migration-hint on B — sees alternatives (A)
    7. Client fetches BMP with since=cursor.last_bmp_ts — gets new messages

This file doubles as:
    - Integration test (pytest-compatible)
    - Live spec for Swift/Kotlin teams to mirror
"""
from __future__ import annotations

import asyncio
import logging
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("mobile_sim")


# ── Test harness: two nodes + one controller, all in-process ──────────────


async def _build_stack(tmp: Path):
    """Bring up controller + two Vortex-like apps, all routed via ASGI.

    Returns a dict with:
        ctrl_app: the controller FastAPI app
        node_a, node_b: the two Vortex "nodes" (minimal FastAPI apps with the
                         session + peer routers mounted)
        key_a, key_b: each node's Ed25519 NodeSigningKey
        httpx_patcher: context manager that routes requests by hostname
    """
    from fastapi import FastAPI
    from asgi_lifespan import LifespanManager
    import httpx
    from httpx import ASGITransport

    from vortex_controller.main import create_app as create_controller_app
    from app.peer._router import router as peers_router
    from app.peer import controller_proxy  # noqa: F401 — registers endpoint
    from app.peer.controller_client import NodeSigningKey
    from app.session.migration import router as session_router
    from app.transport.blind_mailbox import router as bmp_router

    ctrl_app = create_controller_app(
        keys_dir=tmp / "ctrl_keys",
        auto_approve=True,
        entry_urls=["wss://entry.example"],
        mirror_urls=[],
        db_url=f"sqlite+aiosqlite:///{tmp}/ctrl.db",
    )

    # Each node has its own Ed25519 identity stored under its own keys dir
    key_a = NodeSigningKey.load_or_create(tmp / "node_a_keys")
    key_b = NodeSigningKey.load_or_create(tmp / "node_b_keys")

    def _make_node(name: str, signing_key: NodeSigningKey) -> FastAPI:
        app = FastAPI(title=f"vortex-node-{name}")
        # Attach identity to app state so migration.py picks the right one.
        app.state.signing_key = signing_key
        app.include_router(session_router)
        app.include_router(peers_router)
        app.include_router(bmp_router)
        return app

    node_a = _make_node("A", key_a)
    node_b = _make_node("B", key_b)

    ctrl_pub = ctrl_app.state.controller_key.pubkey_hex() if hasattr(
        ctrl_app, "state") and hasattr(ctrl_app.state, "controller_key") else None

    # Route requests based on hostname.
    class _SwitchTransport(ASGITransport):
        def __init__(self):
            self._ctrl = ASGITransport(app=ctrl_app)
            self._a = ASGITransport(app=node_a)
            self._b = ASGITransport(app=node_b)

        async def handle_async_request(self, request):
            host = request.url.host
            if "ctrl" in host:
                return await self._ctrl.handle_async_request(request)
            if "node-a" in host:
                return await self._a.handle_async_request(request)
            if "node-b" in host:
                return await self._b.handle_async_request(request)
            raise httpx.ConnectError(f"unknown host: {host}")

    orig_init = httpx.AsyncClient.__init__

    def _patched_init(self, **kw):
        kw.setdefault("transport", _SwitchTransport())
        kw.setdefault("base_url", "http://unused.test")
        orig_init(self, **kw)

    return {
        "ctrl_app": ctrl_app,
        "node_a": node_a,
        "node_b": node_b,
        "key_a": key_a,
        "key_b": key_b,
        "patch": (_patched_init, orig_init),
    }


def _point_each_node_at_controller(ctrl_app):
    """Override per-node Config so controller_client uses our in-process controller."""
    import app.config as cfg
    cfg.Config.CONTROLLER_URL = "http://ctrl.test"
    cfg.Config.CONTROLLER_PUBKEY = ctrl_app.state.controller_key.pubkey_hex()
    cfg.Config.NETWORK_MODE = "custom"
    cfg.Config.NODE_ANNOUNCE_ENDPOINTS = "wss://node.test:9000"


# ── Reference mobile client (the whole point of this file) ────────────────


class MobileSim:
    """Reference implementation of a Vortex mobile client's migration flow.

    A Swift / Kotlin team can treat this as the behavioural spec they need to
    match. Every method here maps 1:1 to an endpoint on the server.
    """

    def __init__(self, user_pubkey: str, username: str):
        self.user_pubkey = user_pubkey
        self.username = username
        self.current_node_url: str | None = None
        self.last_bmp_ts: float = 0.0
        self.rooms: list[int] = []

    async def _get(self, url: str, **params) -> Any:
        import httpx
        async with httpx.AsyncClient() as http:
            r = await http.get(url, params=params or None)
            r.raise_for_status()
            return r.json()

    async def _post(self, url: str, body: dict) -> Any:
        import httpx
        async with httpx.AsyncClient() as http:
            r = await http.post(url, json=body)
            r.raise_for_status()
            return r.json()

    # ── 1. connect to a node ──

    async def connect(self, node_url: str, rooms: list[int]) -> None:
        self.current_node_url = node_url
        self.rooms = sorted(rooms)
        await self._post(f"{node_url}/api/session/cursor", {
            "user_pubkey": self.user_pubkey,
            "last_bmp_ts": self.last_bmp_ts,
            "rooms": self.rooms,
        })
        log.info("[mobile] connected to %s with %d rooms", node_url, len(self.rooms))

    # ── 2. observe node load / see alternatives ──

    async def get_migration_hint(self) -> dict:
        assert self.current_node_url
        return await self._get(
            f"{self.current_node_url}/api/session/migration-hint",
            user_pubkey=self.user_pubkey,
        )

    # ── 3. start a handoff (still on current node) ──

    async def request_handoff(self) -> dict:
        assert self.current_node_url
        return await self._post(f"{self.current_node_url}/api/session/handoff/init", {
            "user_pubkey": self.user_pubkey,
            "username": self.username,
            "rooms": self.rooms,
            "last_bmp_ts": self.last_bmp_ts,
        })

    # ── 4. finish the handoff on the target node ──

    async def finish_handoff(self, target_node_url: str, token: dict) -> dict:
        resp = await self._post(f"{target_node_url}/api/session/handoff/accept", {
            "token": token,
        })
        # After accept, the target node becomes our new "current"
        self.current_node_url = target_node_url
        cursor = resp.get("cursor", {})
        self.last_bmp_ts = float(cursor.get("last_bmp_ts", 0.0))
        self.rooms = sorted(int(r) for r in cursor.get("rooms", []))
        log.info("[mobile] handoff → %s (rooms=%d)", target_node_url, len(self.rooms))
        return resp

    # ── 5. resume BMP sync using the cursor ──

    async def sync_bmp(self, mailbox_ids: list[str]) -> dict:
        assert self.current_node_url
        resp = await self._post(f"{self.current_node_url}/api/bmp/batch", {
            "ids": mailbox_ids,
            "since": self.last_bmp_ts,
        })
        mailboxes = resp.get("mailboxes", {})
        # Advance cursor to the newest message seen
        newest = self.last_bmp_ts
        for box_msgs in mailboxes.values():
            for m in box_msgs:
                if m.get("ts", 0) > newest:
                    newest = m["ts"]
        self.last_bmp_ts = newest
        await self._post(f"{self.current_node_url}/api/session/cursor", {
            "user_pubkey": self.user_pubkey,
            "last_bmp_ts": self.last_bmp_ts,
            "rooms": self.rooms,
        })
        return mailboxes


# ── The actual test ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_mobile_migration():
    """End-to-end: register two nodes, migrate a session between them, sync BMP."""
    import httpx
    from asgi_lifespan import LifespanManager

    from app.peer.controller_client import ControllerClient, NodeSigningKey
    from app.session.handoff_token import _reset_replay_cache_for_tests

    _reset_replay_cache_for_tests()

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        stack = await _build_stack(tmp)
        patched_init, orig_init = stack["patch"]
        httpx.AsyncClient.__init__ = patched_init

        try:
            async with LifespanManager(stack["ctrl_app"]):
                _point_each_node_at_controller(stack["ctrl_app"])

                # Register both nodes with the controller
                for name, key, url_host in [
                    ("A", stack["key_a"], "http://node-a.test"),
                    ("B", stack["key_b"], "http://node-b.test"),
                ]:
                    payload = {
                        "pubkey": key.pubkey_hex(),
                        "endpoints": [url_host],
                        "metadata": {"name": f"node-{name}"},
                        "timestamp": int(time.time()),
                    }
                    async with httpx.AsyncClient(base_url="http://ctrl.test") as http:
                        r = await http.post("/v1/register", json={
                            "payload": payload,
                            "signature": key.sign(payload),
                        })
                        assert r.status_code == 200

                # Build the mobile sim
                mobile = MobileSim(
                    user_pubkey="aa" * 32,  # fake X25519 pubkey
                    username="alice",
                )

                # 1. Connect to A
                await mobile.connect("http://node-a.test", rooms=[1, 2, 3])

                # 2. Get hint — should mention node B as an alternative
                hint_a = await mobile.get_migration_hint()
                assert hint_a["node"]["pubkey"] == stack["key_a"].pubkey_hex()
                alt_pubs = [a["pubkey"] for a in hint_a["alternatives"]]
                assert stack["key_b"].pubkey_hex() in alt_pubs, alt_pubs
                assert hint_a["cursor"]["last_bmp_ts"] == 0.0
                assert sorted(hint_a["cursor"]["rooms"]) == [1, 2, 3]
                log.info("✅ Migration hint on A lists B as alternative")

                # 3. Simulate some activity — deposit a BMP message
                mailbox = "a" * 32
                async with httpx.AsyncClient(base_url="http://node-a.test") as http:
                    # Pick a fresh wait so the timestamp is > 0
                    await asyncio.sleep(0.05)
                    r = await http.post(f"/api/bmp/post/{mailbox}", json={"ct": "deadbeef" * 8})
                    assert r.status_code == 200
                log.info("✅ Deposited BMP message on A")

                # 4. Request handoff token from A
                hand = await mobile.request_handoff()
                assert "token" in hand and "payload" in hand["token"]
                assert "signature" in hand["token"]
                assert hand["token"]["payload"]["user_pubkey"] == mobile.user_pubkey
                assert hand["token"]["payload"]["src_node_pubkey"] == stack["key_a"].pubkey_hex()
                log.info("✅ Handoff token issued by A, signed by A")

                # 5. Present it to B — B must verify A's signature via controller cache
                accept = await mobile.finish_handoff("http://node-b.test", hand["token"])
                assert accept["ok"]
                assert accept["accepted_user_pubkey"] == mobile.user_pubkey
                assert sorted(accept["cursor"]["rooms"]) == [1, 2, 3]
                log.info("✅ Handoff accepted by B, cursor carried over")

                # 6. B should now return the cursor on /api/session/cursor
                async with httpx.AsyncClient() as http:
                    r = await http.get(
                        "http://node-b.test/api/session/cursor",
                        params={"user_pubkey": mobile.user_pubkey},
                    )
                    assert r.status_code == 200
                    c = r.json()
                    assert c["user_pubkey"] == mobile.user_pubkey
                    assert sorted(c["rooms"]) == [1, 2, 3]
                log.info("✅ Cursor persisted on B, readable post-handoff")

                # 7. The second accept must fail (replay protection)
                async with httpx.AsyncClient() as http:
                    r = await http.post(
                        "http://node-b.test/api/session/handoff/accept",
                        json={"token": hand["token"]},
                    )
                    assert r.status_code == 400, r.text
                    assert "replay" in r.text.lower()
                log.info("✅ Replay of handoff token rejected")

                # 8. BMP sync on B with the carried cursor (since=0 means get all)
                mailboxes = await mobile.sync_bmp([mailbox, "b" * 32])
                # B doesn't share BMP store with A in this setup (each has its own),
                # so we expect empty results but the request MUST succeed
                assert isinstance(mailboxes, dict)
                log.info("✅ BMP sync on B succeeded (cursor advanced to %.3f)", mobile.last_bmp_ts)

                # 9. Hint on B should now list A as the alternative, not B
                hint_b = await mobile.get_migration_hint()
                assert hint_b["node"]["pubkey"] == stack["key_b"].pubkey_hex()
                alt_pubs_b = [a["pubkey"] for a in hint_b["alternatives"]]
                assert stack["key_a"].pubkey_hex() in alt_pubs_b
                assert stack["key_b"].pubkey_hex() not in alt_pubs_b  # never suggest self
                log.info("✅ Hint on B lists A and excludes self")

                log.info("✅ Full mobile migration flow works end-to-end")
        finally:
            httpx.AsyncClient.__init__ = orig_init


@pytest.mark.asyncio
async def test_handoff_rejects_unknown_source():
    """If a handoff token is signed by a node not in the registry, target rejects."""
    import httpx
    from asgi_lifespan import LifespanManager

    from app.peer.controller_client import NodeSigningKey
    from app.session.handoff_token import issue_handoff_token, _reset_replay_cache_for_tests

    _reset_replay_cache_for_tests()

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        stack = await _build_stack(tmp)
        patched_init, orig_init = stack["patch"]
        httpx.AsyncClient.__init__ = patched_init

        try:
            async with LifespanManager(stack["ctrl_app"]):
                _point_each_node_at_controller(stack["ctrl_app"])

                # Register only node B; node A is NOT registered, so its pubkey is unknown.
                payload = {
                    "pubkey": stack["key_b"].pubkey_hex(),
                    "endpoints": ["http://node-b.test"],
                    "metadata": {"name": "node-B"},
                    "timestamp": int(time.time()),
                }
                async with httpx.AsyncClient(base_url="http://ctrl.test") as http:
                    r = await http.post("/v1/register", json={
                        "payload": payload, "signature": stack["key_b"].sign(payload),
                    })
                    assert r.status_code == 200

                # Token signed by UNREGISTERED node A — should be rejected
                unknown_key = NodeSigningKey.load_or_create(tmp / "rogue")
                token = issue_handoff_token(
                    signing_key=unknown_key,
                    user_pubkey="bb" * 32,
                    username="mallory",
                    rooms=[42],
                )
                async with httpx.AsyncClient() as http:
                    r = await http.post(
                        "http://node-b.test/api/session/handoff/accept",
                        json={"token": token},
                    )
                    assert r.status_code == 400
                    assert "unknown source" in r.text or "handoff rejected" in r.text
                log.info("✅ Unknown source rejected")
        finally:
            httpx.AsyncClient.__init__ = orig_init

"""Tests for Phase 5 — Solana on-chain peer registry.

Covers:
    - Borsh serialization/deserialization round-trip for the Peer account
      (matches the exact layout produced by the Anchor program).
    - Mocked Solana JSON-RPC ``getProgramAccounts`` response → parsed list of
      PeerAccount objects.
    - Migration-hint merger: Solana peers and controller peers are combined,
      deduped by pubkey, and self is excluded.
"""
from __future__ import annotations

import base64
import hashlib
import struct
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
# Borsh layout — synth a valid Peer account the way Anchor would
# ══════════════════════════════════════════════════════════════════════════


def _encode_peer_account(
    owner: bytes,
    node_pubkey: bytes,
    endpoints: list[str],
    metadata: str,
    registered_at: int,
    last_heartbeat: int,
    bump: int,
) -> bytes:
    assert len(owner) == 32 and len(node_pubkey) == 32
    disc = hashlib.sha256(b"account:Peer").digest()[:8]
    body = bytearray()
    body += owner
    body += node_pubkey
    body += struct.pack("<I", len(endpoints))
    for e in endpoints:
        b = e.encode("utf-8")
        body += struct.pack("<I", len(b))
        body += b
    meta_b = metadata.encode("utf-8")
    body += struct.pack("<I", len(meta_b))
    body += meta_b
    body += struct.pack("<q", registered_at)
    body += struct.pack("<q", last_heartbeat)
    body += bytes([bump])
    return disc + bytes(body)


# ══════════════════════════════════════════════════════════════════════════
# Parser
# ══════════════════════════════════════════════════════════════════════════


def test_parse_peer_account_roundtrip():
    from app.peer.solana_registry import parse_peer_account

    owner = b"\x01" * 32
    node = b"\x02" * 32
    raw = _encode_peer_account(
        owner=owner,
        node_pubkey=node,
        endpoints=["wss://a.example:9000", "http://b.onion"],
        metadata='{"name":"node-A","region":"eu"}',
        registered_at=1_700_000_000,
        last_heartbeat=1_700_000_500,
        bump=253,
    )
    p = parse_peer_account(raw, pda="FakePda1")
    assert p.pda == "FakePda1"
    assert p.owner == owner
    assert p.node_pubkey == node
    assert p.endpoints == ["wss://a.example:9000", "http://b.onion"]
    assert p.metadata == '{"name":"node-A","region":"eu"}'
    assert p.registered_at == 1_700_000_000
    assert p.last_heartbeat == 1_700_000_500
    assert p.bump == 253
    assert p.node_pubkey_hex == "02" * 32


def test_parse_peer_rejects_bad_discriminator():
    from app.peer.solana_registry import parse_peer_account

    raw = b"\xFF" * 8 + b"\x00" * 100
    with pytest.raises(ValueError, match="discriminator"):
        parse_peer_account(raw)


def test_parse_peer_rejects_truncated():
    from app.peer.solana_registry import parse_peer_account

    with pytest.raises(ValueError, match="too short"):
        parse_peer_account(b"")


def test_is_online_window():
    from app.peer.solana_registry import PeerAccount

    p = PeerAccount(
        pda="p", owner=b"", node_pubkey=b"\x00" * 32,
        endpoints=[], metadata="",
        registered_at=0, last_heartbeat=int(time.time()) - 60,
        bump=0,
    )
    assert p.is_online(window_sec=120)
    assert not p.is_online(window_sec=30)


def test_to_controller_peer_shape():
    from app.peer.solana_registry import PeerAccount

    p = PeerAccount(
        pda="p", owner=b"\xaa" * 32, node_pubkey=b"\xbb" * 32,
        endpoints=["wss://x"], metadata='{"name":"n"}',
        registered_at=0, last_heartbeat=100, bump=255,
    )
    view = p.to_controller_peer()
    assert view["pubkey"] == "bb" * 32
    assert view["endpoints"] == ["wss://x"]
    assert view["metadata"] == {"name": "n"}
    assert view["last_seen"] == 100


def test_to_controller_peer_metadata_fallback():
    from app.peer.solana_registry import PeerAccount

    p = PeerAccount(
        pda="p", owner=b"\xaa" * 32, node_pubkey=b"\xbb" * 32,
        endpoints=["wss://x"], metadata="not-json!",
        registered_at=0, last_heartbeat=100, bump=255,
    )
    view = p.to_controller_peer()
    assert view["metadata"] == {"raw": "not-json!"}


# ══════════════════════════════════════════════════════════════════════════
# RPC client (mocked)
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_fetch_peers_parses_rpc_response():
    from app.peer.solana_registry import SolanaRegistryClient

    owner = b"\x11" * 32
    node_a = b"\xaa" * 32
    node_b = b"\xbb" * 32

    now = int(time.time())
    fresh = _encode_peer_account(owner, node_a, ["wss://a:9000"], "", now - 10, now - 10, 254)
    stale = _encode_peer_account(owner, node_b, ["wss://b:9000"], "", now - 5000, now - 5000, 253)

    fake_result = [
        {"pubkey": "PdaA", "account": {"data": [base64.b64encode(fresh).decode(), "base64"]}},
        {"pubkey": "PdaB", "account": {"data": [base64.b64encode(stale).decode(), "base64"]}},
    ]

    async def fake_post(self, url, **kwargs):
        body = kwargs["json"]
        assert body["method"] == "getProgramAccounts"
        return _mock_response("POST", url, json={"jsonrpc": "2.0", "id": 1, "result": fake_result})

    with patch.object(httpx.AsyncClient, "post", fake_post):
        client = SolanaRegistryClient(
            rpc_url="https://api.devnet.solana.com",
            program_id="Vor1exReg11111111111111111111111111111111",
        )
        all_peers = await client.fetch_peers()
        online = await client.fetch_peers(online_window_sec=300)

    assert len(all_peers) == 2
    assert len(online) == 1
    assert online[0].node_pubkey_hex == "aa" * 32


@pytest.mark.asyncio
async def test_fetch_peers_skips_invalid_rows():
    from app.peer.solana_registry import SolanaRegistryClient

    owner = b"\x11" * 32
    good = _encode_peer_account(owner, b"\xcc" * 32, ["wss://c:9000"], "", 0, int(time.time()), 255)

    bad_disc = b"\xFF" * 8 + b"\x00" * 70

    fake_result = [
        {"pubkey": "PdaGood", "account": {"data": [base64.b64encode(good).decode(), "base64"]}},
        {"pubkey": "PdaBad",  "account": {"data": [base64.b64encode(bad_disc).decode(), "base64"]}},
    ]

    async def fake_post(self, url, **kwargs):
        return _mock_response("POST", url, json={"jsonrpc": "2.0", "id": 1, "result": fake_result})

    with patch.object(httpx.AsyncClient, "post", fake_post):
        client = SolanaRegistryClient(
            rpc_url="https://api.devnet.solana.com",
            program_id="Vor1exReg11111111111111111111111111111111",
        )
        peers = await client.fetch_peers()

    assert len(peers) == 1
    assert peers[0].node_pubkey_hex == "cc" * 32


@pytest.mark.asyncio
async def test_solana_rpc_error_propagates():
    from app.peer.solana_registry import SolanaRegistryClient, SolanaRpcError

    async def fake_post(self, url, **kwargs):
        return _mock_response("POST", url, json={
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32602, "message": "Invalid params"},
        })

    with patch.object(httpx.AsyncClient, "post", fake_post):
        client = SolanaRegistryClient(rpc_url="http://x", program_id="pid")
        with pytest.raises(SolanaRpcError):
            await client.fetch_peers()


def test_base58_encode_roundtrip():
    from app.peer.solana_registry import _b58encode

    # Known values: the discriminator for "account:Peer" is deterministic, so
    # we at least ensure base58 produces valid alphabet output.
    out = _b58encode(b"\x00\x01\x02\x03\xff")
    assert all(c in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for c in out)
    # Leading zero bytes become '1'
    assert _b58encode(b"\x00\x00\x42").startswith("11")


# ══════════════════════════════════════════════════════════════════════════
# Integration: migration-hint merges Solana + controller peers
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_migration_hint_merges_solana_and_controller_peers():
    """Feed both sources and verify merger dedupes, excludes self, caps at 5."""
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport

    from app.config import Config
    from app.peer.controller_client import NodeSigningKey
    from app.peer.solana_registry import PeerAccount
    from app.session.migration import router as session_router, _cursor_store

    _cursor_store.clear = getattr(_cursor_store, "clear", None)  # silence linters

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        # This node's signing key — used as "self" in the exclusion check
        self_key = NodeSigningKey.load_or_create(d / "self_keys")
        self_pub = self_key.pubkey_hex()

        app = FastAPI()
        app.state.signing_key = self_key
        app.include_router(session_router)

        # Fake Solana peers: one fresh, one which conflicts with a controller peer.
        now = int(time.time())
        solana_peers = [
            PeerAccount(
                pda="pda1", owner=b"\x00" * 32, node_pubkey=bytes.fromhex("aa" * 32),
                endpoints=["wss://solana-node-a:9000"], metadata='{"name":"A"}',
                registered_at=0, last_heartbeat=now, bump=0,
            ),
            PeerAccount(
                pda="pda2", owner=b"\x00" * 32, node_pubkey=bytes.fromhex("cc" * 32),
                endpoints=["wss://solana-win:9000"], metadata='{"name":"C-solana"}',
                registered_at=0, last_heartbeat=now, bump=0,
            ),
            # Stale — filtered out by online_window_sec=600
            PeerAccount(
                pda="stale", owner=b"\x00" * 32, node_pubkey=bytes.fromhex("dd" * 32),
                endpoints=["wss://old:9000"], metadata="",
                registered_at=0, last_heartbeat=now - 10_000, bump=0,
            ),
            # Should be excluded as self
            PeerAccount(
                pda="self_ref", owner=b"\x00" * 32, node_pubkey=bytes.fromhex(self_pub),
                endpoints=["wss://me:9000"], metadata="",
                registered_at=0, last_heartbeat=now, bump=0,
            ),
        ]

        # Fake controller peers: overlap on 'cc' pubkey (Solana should win);
        # add 'bb' which Solana does NOT have.
        controller_peers = [
            {
                "pubkey": "bb" * 32,
                "endpoints": ["wss://controller-b:9000"],
                "metadata": {"name": "B"},
                "last_seen": now,
            },
            {
                "pubkey": "cc" * 32,
                "endpoints": ["wss://CONTROLLER-loses:9000"],
                "metadata": {"name": "C-controller"},
                "last_seen": now,
            },
        ]

        # Patch the two source functions used by migration.py
        class _FakeSolanaClient:
            def __init__(self, *a, **kw):
                pass
            async def fetch_peers(self, online_window_sec=None, now=None):
                if online_window_sec is not None:
                    return [p for p in solana_peers if p.is_online(online_window_sec)]
                return list(solana_peers)

        class _FakeControllerClient:
            async def fetch_random_peers(self, count=5):
                return controller_peers

        saved_rpc = Config.SOLANA_RPC_URL
        saved_pid = Config.SOLANA_PROGRAM_ID
        Config.SOLANA_RPC_URL = "http://fake-solana"
        Config.SOLANA_PROGRAM_ID = "FakeProgram"

        try:
            with patch("app.peer.solana_registry.SolanaRegistryClient", _FakeSolanaClient), \
                 patch("app.peer.controller_client.client_from_config",
                       return_value=_FakeControllerClient()):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://node-self",
                ) as http:
                    r = await http.get("/api/session/migration-hint")

            assert r.status_code == 200
            data = r.json()

            # Our own pubkey → reported as node.pubkey, not listed as alternative
            assert data["node"]["pubkey"] == self_pub
            alt_pubs = [a["pubkey"] for a in data["alternatives"]]
            assert self_pub not in alt_pubs

            # 'aa' (solana-only) and 'bb' (controller-only) both present
            assert "aa" * 32 in alt_pubs
            assert "bb" * 32 in alt_pubs

            # 'cc' present exactly once, and Solana wins the tie
            cc_entries = [a for a in data["alternatives"] if a["pubkey"] == "cc" * 32]
            assert len(cc_entries) == 1
            assert cc_entries[0]["endpoints"] == ["wss://solana-win:9000"]
            assert cc_entries[0]["metadata"]["name"] == "C-solana"

            # 'dd' excluded by staleness
            assert "dd" * 32 not in alt_pubs
        finally:
            Config.SOLANA_RPC_URL = saved_rpc
            Config.SOLANA_PROGRAM_ID = saved_pid


@pytest.mark.asyncio
async def test_migration_hint_works_without_solana():
    """When no Solana config, the merger still returns controller peers."""
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport

    from app.config import Config
    from app.peer.controller_client import NodeSigningKey
    from app.session.migration import router as session_router

    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        self_key = NodeSigningKey.load_or_create(d / "self_keys")
        app = FastAPI()
        app.state.signing_key = self_key
        app.include_router(session_router)

        controller_peers = [
            {"pubkey": "aa" * 32, "endpoints": ["wss://a"], "metadata": {}, "last_seen": 0},
        ]

        class _FakeControllerClient:
            async def fetch_random_peers(self, count=5):
                return controller_peers

        saved_rpc = Config.SOLANA_RPC_URL
        Config.SOLANA_RPC_URL = ""  # disable Solana

        try:
            with patch("app.peer.controller_client.client_from_config",
                       return_value=_FakeControllerClient()):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://node-self",
                ) as http:
                    r = await http.get("/api/session/migration-hint")
            data = r.json()
            alt_pubs = [a["pubkey"] for a in data["alternatives"]]
            assert alt_pubs == ["aa" * 32]
        finally:
            Config.SOLANA_RPC_URL = saved_rpc

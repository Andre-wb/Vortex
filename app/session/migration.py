"""Session migration API — moves a user cleanly between Vortex nodes.

Endpoints (registered under ``/api/session``):

    GET  /migration-hint          hint about this node's load + alternatives
    POST /handoff/init            source node issues handoff token
    POST /handoff/accept          target node accepts handoff token
    POST /cursor                  persist client cursor (BMP ts + rooms)
    GET  /cursor                  read back last cursor

The handoff token is signed by the source node's Ed25519 identity (the same
one used with the controller in Phase 1). The target node verifies it against
either its locally cached peer registry or the controller.

This module is intentionally *stateless in HTTP* — the only persistent state
is the per-user ``SessionCursor`` (last BMP timestamp + subscribed rooms) so a
reconnecting client can resume without losing messages.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.config import Config
from app.peer.controller_client import NodeSigningKey
from app.session.handoff_token import (
    HandoffError,
    issue_handoff_token,
    verify_handoff_token,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/session", tags=["session"])


# ══════════════════════════════════════════════════════════════════════════
# Per-user cursor (in-memory; a real deployment would back this with Redis)
# ══════════════════════════════════════════════════════════════════════════

class SessionCursor(BaseModel):
    user_pubkey: str
    last_bmp_ts: float = 0.0
    rooms: list[int] = Field(default_factory=list)
    updated_at: float = 0.0


class _CursorStore:
    """In-memory store keyed by user_pubkey. Thread-safe for single process."""

    def __init__(self) -> None:
        self._by_user: dict[str, SessionCursor] = {}

    def set(self, cursor: SessionCursor) -> None:
        cursor.updated_at = time.time()
        self._by_user[cursor.user_pubkey] = cursor

    def get(self, user_pubkey: str) -> Optional[SessionCursor]:
        return self._by_user.get(user_pubkey)

    def clear(self, user_pubkey: str) -> None:
        self._by_user.pop(user_pubkey, None)


_cursor_store = _CursorStore()


# ══════════════════════════════════════════════════════════════════════════
# Load / health signal
# ══════════════════════════════════════════════════════════════════════════

class _NodeLoad:
    """Very rough load estimate — enough for "go elsewhere" hints.

    For a real deployment, wire this to connection_manager counts, CPU gauge,
    etc. For now we just count active WS connections and return load = conn /
    max_conn.
    """

    MAX_CONN = 10_000

    # Above this fraction of MAX_CONN, new sessions are refused with 503
    # pointing at alternatives.
    SHED_LOAD_THRESHOLD = 0.85
    # Above this, existing sessions get a WS migrate_suggest push (Phase 6).
    MIGRATION_SUGGEST_THRESHOLD = 0.80

    def snapshot(self) -> dict:
        conn_count = _active_ws_count()
        load = min(1.0, conn_count / self.MAX_CONN) if self.MAX_CONN else 0.0
        return {
            "connections": conn_count,
            "load": round(load, 3),
            "accepts_new": load < self.SHED_LOAD_THRESHOLD,
            "mode": Config.NETWORK_MODE,
        }

    def is_overloaded(self) -> bool:
        return not self.snapshot()["accepts_new"]

    def should_suggest_migration(self) -> bool:
        return self.snapshot()["load"] >= self.MIGRATION_SUGGEST_THRESHOLD


def _active_ws_count() -> int:
    """Count active WS connections via the existing ConnectionManager, if any."""
    try:
        from app.peer.connection_manager import manager as _mgr
        # ConnectionManager tracks users in `.rooms` (room_id → list of users)
        rooms = getattr(_mgr, "rooms", {}) or {}
        return sum(len(v) for v in rooms.values())
    except Exception:
        return 0


_load = _NodeLoad()


# ══════════════════════════════════════════════════════════════════════════
# Peer pubkey resolver (source-node trust for handoff)
# ══════════════════════════════════════════════════════════════════════════

def _default_source_resolver() -> "SourceResolver":
    """Build a resolver from whatever context this node has.

    Priority:
        1. Cached controller peer list (fast path, works offline from controller)
        2. Live controller lookup (network fetch on demand)
        3. BOOTSTRAP_PEERS env — treat as trusted
    """
    return SourceResolver()


class SourceResolver:
    """Decides whether a given source-node pubkey is trusted.

    A node is "trusted" if any of:
        - It's present in our cached peer list (from controller_client)
        - It's listed in BOOTSTRAP_PEERS config
        - A live controller lookup succeeds
    """

    def __init__(self) -> None:
        self._cached: set[str] = set()
        self._cached_until: float = 0.0

    async def warm(self) -> None:
        """Refresh the cache from the controller (best-effort)."""
        from app.peer.controller_client import client_from_config
        client = client_from_config()
        if not client:
            return
        try:
            peers = await client.fetch_random_peers(count=32)
            self._cached = {p.get("pubkey", "").lower() for p in peers if p.get("pubkey")}
            self._cached_until = time.time() + 300
        except Exception as e:
            logger.debug("SourceResolver warm failed: %s", e)

    def __call__(self, pubkey_hex: str) -> bool:
        pub = (pubkey_hex or "").lower()
        if not pub:
            return False
        if pub in self._cached:
            return True
        # bootstrap peers are URLs, not pubkeys — can't compare directly, so
        # fall through. The controller-cache is the primary trust source.
        return False


_resolver = _default_source_resolver()


# ══════════════════════════════════════════════════════════════════════════
# Request / response models
# ══════════════════════════════════════════════════════════════════════════

class MigrationHintAlt(BaseModel):
    pubkey: str
    endpoints: list[str]
    metadata: dict = Field(default_factory=dict)
    last_seen: int = 0


class MigrationHintResponse(BaseModel):
    node: dict
    alternatives: list[MigrationHintAlt]
    cursor: Optional[SessionCursor] = None


class HandoffInitRequest(BaseModel):
    user_pubkey: str = Field(..., description="client's long-term X25519 pubkey, hex")
    username: str = ""
    rooms: list[int] = Field(default_factory=list)
    last_bmp_ts: float = 0.0


class HandoffInitResponse(BaseModel):
    token: dict
    # The target node should choose from these alternatives (or use any
    # controller-provided node). Included for convenience.
    suggested_targets: list[MigrationHintAlt] = Field(default_factory=list)


class HandoffAcceptRequest(BaseModel):
    token: dict


class HandoffAcceptResponse(BaseModel):
    ok: bool
    accepted_user_pubkey: str
    cursor: SessionCursor


class CursorSetRequest(BaseModel):
    user_pubkey: str
    last_bmp_ts: float = 0.0
    rooms: list[int] = Field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════════

def _require_signing_key(request: Optional[Request] = None) -> NodeSigningKey:
    """Load the node's Ed25519 signing key (shared with controller_client).

    If the hosting FastAPI app has stored a key on ``app.state.signing_key``
    (useful for tests that run multiple nodes in one process), prefer that.
    Otherwise fall back to the on-disk key under ``Config.KEYS_DIR``.
    """
    if request is not None:
        sk = getattr(request.app.state, "signing_key", None)
        if isinstance(sk, NodeSigningKey):
            return sk
    return NodeSigningKey.load_or_create(Config.KEYS_DIR)


@router.get("/migration-hint", response_model=MigrationHintResponse)
async def migration_hint(
    request: Request,
    user_pubkey: Optional[str] = None,
) -> MigrationHintResponse:
    """Return this node's load plus alternative nodes the client can use.

    Pass ``?user_pubkey=<hex>`` to also get back the persisted cursor so a
    reconnecting client can resume. The pubkey does not authenticate anything
    here — the cursor is not sensitive (client already knows its own state).

    Peer alternatives are merged from all configured discovery channels:
        1. HTTP controller (Phase 1) — if ``CONTROLLER_URL`` is set
        2. Solana on-chain registry (Phase 5) — if ``SOLANA_RPC_URL`` is set
    The merger dedupes by ``pubkey`` and prefers Solana (on-chain is
    authoritative; controller may lag).
    """
    snap = _load.snapshot()
    my_pub = _require_signing_key(request).pubkey_hex()
    snap["pubkey"] = my_pub

    alternatives = await _collect_alternatives(my_pub)
    cursor = _cursor_store.get(user_pubkey) if user_pubkey else None
    return MigrationHintResponse(node=snap, alternatives=alternatives, cursor=cursor)


async def _collect_alternatives(self_pubkey: str) -> list[MigrationHintAlt]:
    """Merge peer lists from all configured discovery sources.

    Returns up to 5 alternatives; never includes ``self_pubkey``. Solana
    entries take precedence over controller entries when the pubkey matches,
    because on-chain data is authoritative.
    """
    self_pub = (self_pubkey or "").lower()

    solana_task = _fetch_solana_alternatives(self_pub)
    controller_task = _fetch_controller_alternatives(self_pub)
    solana_peers, controller_peers = await _gather_best_effort(
        solana_task, controller_task,
    )

    merged: dict[str, MigrationHintAlt] = {}
    for peer in solana_peers:
        merged[peer.pubkey.lower()] = peer
    for peer in controller_peers:
        merged.setdefault(peer.pubkey.lower(), peer)
    merged.pop(self_pub, None)
    return list(merged.values())[:5]


async def _gather_best_effort(*coros) -> list[list]:
    """asyncio.gather that swallows per-coro exceptions and returns [] for them."""
    import asyncio

    async def _wrap(c):
        try:
            return await c
        except Exception as e:
            logger.debug("alternatives source failed: %s", e)
            return []

    return await asyncio.gather(*(_wrap(c) for c in coros))


async def _fetch_controller_alternatives(self_pub: str) -> list[MigrationHintAlt]:
    from app.peer.controller_client import client_from_config
    client = client_from_config()
    if not client:
        return []
    peers = await client.fetch_random_peers(count=5)
    return [
        MigrationHintAlt(
            pubkey=p.get("pubkey", ""),
            endpoints=p.get("endpoints", []),
            metadata=p.get("metadata", {}),
            last_seen=p.get("last_seen", 0),
        )
        for p in peers
        if p.get("pubkey", "").lower() != self_pub
    ]


async def _fetch_solana_alternatives(self_pub: str) -> list[MigrationHintAlt]:
    if not (Config.SOLANA_RPC_URL and Config.SOLANA_PROGRAM_ID):
        return []
    from app.peer.solana_registry import SolanaRegistryClient
    client = SolanaRegistryClient(
        rpc_url=Config.SOLANA_RPC_URL,
        program_id=Config.SOLANA_PROGRAM_ID,
    )
    peers = await client.fetch_peers(online_window_sec=600)
    out: list[MigrationHintAlt] = []
    for p in peers:
        if p.node_pubkey_hex.lower() == self_pub:
            continue
        view = p.to_controller_peer()
        out.append(MigrationHintAlt(
            pubkey=view["pubkey"],
            endpoints=view["endpoints"],
            metadata=view["metadata"],
            last_seen=view["last_seen"],
        ))
    return out


@router.post("/handoff/init", response_model=HandoffInitResponse)
async def handoff_init(body: HandoffInitRequest, request: Request) -> HandoffInitResponse:
    """Issue a signed handoff token for this user.

    The client calls this on its *current* (source) node, receives the signed
    token, then presents it to a *target* node.

    For MVP the only check is that the client declared its own user_pubkey —
    the target node will re-verify the envelope signature on accept, which
    proves the token came from *this* node. The client's ``user_pubkey`` is
    transferred as-is; it's the client's responsibility to match it to its own
    identity.
    """
    if not body.user_pubkey or len(body.user_pubkey) > 128:
        raise HTTPException(400, "user_pubkey required (max 128 chars)")

    signing_key = _require_signing_key(request)

    # Persist cursor so a later `/cursor` read picks up the same state.
    cursor = SessionCursor(
        user_pubkey=body.user_pubkey,
        last_bmp_ts=float(body.last_bmp_ts or 0.0),
        rooms=list(body.rooms or []),
    )
    _cursor_store.set(cursor)

    token = issue_handoff_token(
        signing_key=signing_key,
        user_pubkey=body.user_pubkey,
        username=body.username or "",
        rooms=body.rooms,
        last_bmp_ts=body.last_bmp_ts,
    )

    # Pull alternatives (merged from controller + Solana) so the client
    # doesn't need a second round-trip.
    suggested = await _collect_alternatives(signing_key.pubkey_hex())
    return HandoffInitResponse(token=token, suggested_targets=suggested)


@router.post("/handoff/accept", response_model=HandoffAcceptResponse)
async def handoff_accept(body: HandoffAcceptRequest, request: Request) -> HandoffAcceptResponse:
    """Accept a handoff token issued by another node.

    Refuses (503 + alternatives) if this node is already overloaded, so the
    client picks a different target instead of piling onto a hot node.
    """
    if _load.is_overloaded():
        alternatives = await _collect_alternatives(
            _require_signing_key(request).pubkey_hex()
        )
        raise HTTPException(
            status_code=503,
            headers={"Retry-After": "0", "X-Vortex-Reason": "overloaded"},
            detail={
                "error": "overloaded",
                "load": _load.snapshot()["load"],
                "alternatives": [a.model_dump() for a in alternatives],
            },
        )

    # Make sure our peer cache is warm before verifying
    await _resolver.warm()

    try:
        payload = verify_handoff_token(body.token, _resolver)
    except HandoffError as e:
        raise HTTPException(400, f"handoff rejected: {e}")

    user_pubkey = payload["user_pubkey"]
    cursor_data = payload.get("cursor", {}) or {}
    cursor = SessionCursor(
        user_pubkey=user_pubkey,
        last_bmp_ts=float(cursor_data.get("last_bmp_ts", 0.0)),
        rooms=list(cursor_data.get("rooms", [])),
    )
    _cursor_store.set(cursor)
    logger.info(
        "handoff accepted: user=%s from src=%s rooms=%d",
        user_pubkey[:16],
        payload["src_node_pubkey"][:16],
        len(cursor.rooms),
    )
    return HandoffAcceptResponse(
        ok=True,
        accepted_user_pubkey=user_pubkey,
        cursor=cursor,
    )


@router.post("/cursor", response_model=SessionCursor)
async def set_cursor(body: CursorSetRequest) -> SessionCursor:
    """Client updates its resume cursor after each successful sync."""
    if not body.user_pubkey or len(body.user_pubkey) > 128:
        raise HTTPException(400, "user_pubkey required")
    cursor = SessionCursor(
        user_pubkey=body.user_pubkey,
        last_bmp_ts=max(0.0, float(body.last_bmp_ts or 0.0)),
        rooms=sorted(int(r) for r in body.rooms or []),
    )
    _cursor_store.set(cursor)
    return cursor


@router.get("/cursor", response_model=Optional[SessionCursor])
async def get_cursor(user_pubkey: str) -> Optional[SessionCursor]:
    """Return the last known cursor for a user (or null if unknown)."""
    if not user_pubkey:
        raise HTTPException(400, "user_pubkey required")
    return _cursor_store.get(user_pubkey)

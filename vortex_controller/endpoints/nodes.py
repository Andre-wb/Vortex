"""GET /v1/nodes/random and /v1/nodes/lookup/{pubkey}.

Both responses are wrapped in a controller-signed envelope so clients can
verify authenticity even if the transport is compromised.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from ..controller_crypto import sign_response

router = APIRouter(prefix="/v1/nodes", tags=["nodes"])


def _node_public_view(row: dict) -> dict:
    return {
        "pubkey": row["pubkey_hex"],
        "endpoints": row["endpoints"],
        "metadata": row["metadata"],
        "last_seen": row["last_heartbeat"],
    }


@router.get("/random")
async def random_nodes(
    request: Request,
    count: int = Query(5, ge=1, le=32),
) -> dict:
    storage = request.app.state.storage
    key = request.app.state.controller_key

    rows = await storage.random_online(count)
    payload = {
        "nodes": [_node_public_view(r) for r in rows],
        "count": len(rows),
    }
    return sign_response(key, payload)


@router.get("/lookup/{pubkey}")
async def lookup(pubkey: str, request: Request) -> dict:
    storage = request.app.state.storage
    key = request.app.state.controller_key

    row = await storage.get(pubkey)
    if not row:
        raise HTTPException(404, "node not found")
    payload = {"node": _node_public_view(row)}
    return sign_response(key, payload)

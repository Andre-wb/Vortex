"""
app/transport/global_routes.py — API endpoints for global mode (gossip, bootstrap, search).

These routes are available only when NETWORK_MODE=global.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.config import Config
from app.models import User
from app.security.auth_jwt import get_current_user
from app.transport.global_transport import global_transport

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/global", tags=["global"])

# ── Per-IP rate limiter for gossip / bootstrap ────────────────────────────────
_gossip_rate: dict[str, list] = {}  # ip -> [timestamp, count]
GOSSIP_RATE_LIMIT = 10  # requests per minute


def _check_gossip_rate(ip: str) -> bool:
    """Return True if the request is within rate limits."""
    now = time.monotonic()
    bucket = _gossip_rate.get(ip)
    if bucket and now - bucket[0] < 60.0:
        bucket[1] += 1
        return bucket[1] <= GOSSIP_RATE_LIMIT
    _gossip_rate[ip] = [now, 1]
    return True


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic schemas
# ══════════════════════════════════════════════════════════════════════════════

class GossipRequest(BaseModel):
    """Incoming gossip request: peer list + rooms from another node."""
    sender_ip: str = Field(..., description="Sender IP")
    sender_port: int = Field(..., description="Sender port")
    sender_pubkey: str = Field("", description="X25519 pubkey of sender (hex)")
    peers: list[dict] = Field(default_factory=list, max_length=500, description="Sender's peer list")
    rooms: list[dict] = Field(default_factory=list, max_length=1000, description="Sender's public rooms")


class BootstrapRequest(BaseModel):
    """Request for initial connection to the network."""
    sender_ip: str = Field(..., description="New node IP")
    sender_port: int = Field(..., description="New node port")
    sender_pubkey: str = Field("", description="X25519 pubkey of new node (hex)")


class AddPeerRequest(BaseModel):
    """Manual peer addition (from QR code or manual input)."""
    ip: str = Field(..., description="Peer IP")
    port: int = Field(9000, description="Peer port")


# ══════════════════════════════════════════════════════════════════════════════
# Gossip endpoint (accepts from any node without authentication)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/gossip")
async def gossip(body: GossipRequest, request: Request):
    """
    Receive a gossip packet from another node.
    Exchange peer lists and rooms to form a mesh network.
    Does not require authentication — this is an inter-node protocol.
    """
    # Per-IP rate limit
    client_ip = request.client.host if request.client else body.sender_ip
    if not _check_gossip_rate(client_ip):
        raise HTTPException(429, "Rate limit exceeded")

    # Validate sender_pubkey — must be 64-char hex or empty string
    if body.sender_pubkey:
        if len(body.sender_pubkey) != 64:
            raise HTTPException(400, "Invalid sender pubkey length")
        try:
            bytes.fromhex(body.sender_pubkey)
        except ValueError:
            raise HTTPException(400, "Invalid pubkey hex")

    # Always use real IP from TCP connection (spoof protection)
    real_ip = request.client.host if request.client else body.sender_ip

    result = global_transport.handle_gossip(
        sender_ip=real_ip,
        sender_port=body.sender_port,
        sender_pubkey=body.sender_pubkey,
        peers=body.peers,
        rooms=body.rooms,
    )

    # Add our rooms to the response
    our_rooms = await global_transport._get_our_public_rooms()
    result["rooms"] = our_rooms

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Bootstrap endpoint (initial connection)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/bootstrap")
async def bootstrap(body: BootstrapRequest, request: Request):
    """
    Initial connection of a new node to the mesh network.
    Returns node info + current peer list.
    Does not require authentication.
    """
    # Per-IP rate limit
    client_ip = request.client.host if request.client else body.sender_ip
    if not _check_gossip_rate(client_ip):
        raise HTTPException(429, "Rate limit exceeded")

    # Validate sender_pubkey — must be 64-char hex or empty string
    if body.sender_pubkey:
        if len(body.sender_pubkey) != 64:
            raise HTTPException(400, "Invalid sender pubkey length")
        try:
            bytes.fromhex(body.sender_pubkey)
        except ValueError:
            raise HTTPException(400, "Invalid pubkey hex")

    real_ip = body.sender_ip
    if request.client and request.client.host:
        client_ip = request.client.host
        if client_ip not in ("127.0.0.1", "0.0.0.0"):
            real_ip = client_ip

    result = global_transport.handle_bootstrap(
        sender_ip=real_ip,
        sender_port=body.sender_port,
        sender_pubkey=body.sender_pubkey,
    )

    # Add our public rooms
    result["rooms"] = await global_transport._get_our_public_rooms()

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Room search
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/search-rooms")
async def search_rooms_local(q: str = Query("", description="Search query")):
    """
    Search public rooms ON THIS node by name.
    Called by other nodes via the gossip protocol.
    Does not require authentication — this is an inter-node request.
    """
    try:
        from app.database import SessionLocal
        from app.models_rooms import Room
        db = SessionLocal()
        try:
            query = db.query(Room).filter(Room.is_private == False)
            if q:
                query = query.filter(Room.name.ilike(f"%{q}%"))
            rooms = query.all()
            return {
                "rooms": [
                    {
                        "id": r.id,
                        "name": r.name,
                        "description": r.description or "",
                        "invite_code": r.invite_code,
                        "is_channel": getattr(r, "is_channel", False),
                        "is_voice": getattr(r, "is_voice", False),
                        "avatar_emoji": getattr(r, "avatar_emoji", "") or "",
                        "avatar_url": getattr(r, "avatar_url", "") or "",
                        "member_count": r.member_count() if callable(getattr(r, "member_count", None)) else 0,
                    }
                    for r in rooms
                ]
            }
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Room search error: {e}")
        return {"rooms": []}


@router.get("/search-rooms-global")
async def search_rooms_global(
    q: str = Query("", description="Search query"),
    u: User = Depends(get_current_user),
):
    """
    Global room search across ALL known peers.
    Requires authentication — called by the client.
    """
    rooms = await global_transport.search_rooms(q)
    return {
        "rooms": rooms,
        "peers_searched": global_transport.peer_count(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Node info
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/node-info")
async def node_info():
    """
    Public information about this node.
    Used for ping and availability checks.
    Does not require authentication.
    """
    try:
        from app.security.crypto import load_or_create_node_keypair
        _, pub = load_or_create_node_keypair(Config.KEYS_DIR)
        pubkey = pub.hex() if isinstance(pub, bytes) else bytes(pub).hex()
    except Exception:
        pubkey = ""

    return {
        "version": "3.0.0",
        "network_mode": Config.NETWORK_MODE,
        "node_pubkey": pubkey,
        "peers": global_transport.peer_count(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Peer management (requires authentication)
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/peers")
async def list_global_peers(u: User = Depends(get_current_user)):
    """List of all known global peers."""
    peers = global_transport.get_peers()
    return {
        "count": len(peers),
        "peers": [
            {
                "ip": p.ip,
                "port": p.port,
                "pubkey": p.node_pubkey_hex[:16] + "..." if p.node_pubkey_hex else None,
                "last_seen_ago": round((__import__("time").time() - p.last_seen), 1),
                "rooms_count": len(p.rooms),
                "alive": p.alive(),
            }
            for p in peers
        ],
    }


@router.get("/cdn-status")
async def cdn_status(u: User = Depends(get_current_user)):
    """CDN relay status (Multi-CDN failover)."""
    from app.transport.cdn_relay import cdn_config
    return cdn_config.get_status()


@router.post("/add-peer")
async def add_peer(body: AddPeerRequest, u: User = Depends(get_current_user)):
    """
    Manual peer addition (from QR code or IP input).
    Requires authentication.
    """
    ok = await global_transport.add_bootstrap_peer(body.ip, body.port)
    return {
        "ok": ok,
        "addr": f"{body.ip}:{body.port}",
        "total_peers": global_transport.peer_count(),
    }

"""
app/peer/peer_federation.py — Federated join & Multihop join routes.

Uses a shared HTTP connection pool for all federation requests
to avoid per-request SSL handshake overhead (saves ~200-500ms per call).
"""
from __future__ import annotations

import logging
import time

import httpx
from fastapi import Depends, HTTPException
from pydantic import BaseModel

from app.config import Config
from app.models import User
from app.peer._router import router
from app.peer.peer_models import registry
from app.security.auth_jwt import get_current_user
from app.security.ssl_context import make_peer_ssl_context

logger = logging.getLogger(__name__)

# ── Shared HTTP connection pool (keep-alive, connection reuse) ──────────────
_federation_pool = httpx.AsyncClient(
    timeout=httpx.Timeout(8.0, connect=4.0),
    limits=httpx.Limits(max_keepalive_connections=20, max_connections=100, keepalive_expiry=30.0),
    verify=make_peer_ssl_context(),
)

# ── JWT cache for federation guest logins (peer_key → {jwt, expires}) ───────
_jwt_cache: dict[str, dict] = {}
_JWT_CACHE_TTL = 240  # 4 minutes (tokens usually last 5+ min)


# ══════════════════════════════════════════════════════════════════════════════
# Federated join
# ══════════════════════════════════════════════════════════════════════════════

class FederatedJoinRequest(BaseModel):
    invite_code: str
    peer_ip:     str
    peer_port:   int


@router.post("/federated-join")
async def federated_join(body: FederatedJoinRequest, u: User = Depends(get_current_user)):
    remote_base = None
    for scheme in ("https", "http"):
        try:
            r = await _federation_pool.get(
                f"{scheme}://{body.peer_ip}:{body.peer_port}/api/peers/status"
            )
            if r.status_code == 200:
                remote_base = f"{scheme}://{body.peer_ip}:{body.peer_port}"
                break
        except Exception:
            continue

    if not remote_base:
        raise HTTPException(503, f"Node {body.peer_ip}:{body.peer_port} is unreachable")

    # ── Cached guest-login JWT (skip if recently authenticated) ──────────
    cache_key = f"{remote_base}:{u.username}"
    cached = _jwt_cache.get(cache_key)
    if cached and cached["expires"] > time.monotonic():
        remote_jwt = cached["jwt"]
    else:
        try:
            resp = await _federation_pool.post(
                f"{remote_base}/api/federation/guest-login",
                json={
                    "username":      u.username,
                    "display_name":  u.display_name,
                    "avatar_emoji":  u.avatar_emoji,
                    "x25519_pubkey": u.x25519_public_key or "",
                    "peer_port":     Config.PORT,
                },
            )
        except Exception as e:
            raise HTTPException(502, f"Node connection error: {e}")

        if resp.status_code == 403:
            raise HTTPException(
                403,
                "Удалённый узел не распознал этот узел. "
                "Подождите ~10 секунд (UDP discovery) и попробуйте снова."
            )
        if resp.status_code != 200:
            raise HTTPException(502, f"guest-login: {resp.status_code} {resp.text[:200]}")

        remote_jwt = resp.json()["access_token"]
        _jwt_cache[cache_key] = {"jwt": remote_jwt, "expires": time.monotonic() + _JWT_CACHE_TTL}

    try:
        join_resp = await _federation_pool.post(
            f"{remote_base}/api/rooms/join/{body.invite_code.upper()}",
            headers={"Authorization": f"Bearer {remote_jwt}"},
            json={},
            )
    except Exception as e:
        raise HTTPException(502, f"Join error: {e}")

    if join_resp.status_code not in (200, 201):
        raise HTTPException(join_resp.status_code, join_resp.text[:200])

    room_info      = join_resp.json().get("room", {})
    remote_room_id = room_info.get("id")
    if not remote_room_id:
        raise HTTPException(502, "Remote node did not return room_id")

    from app.federation.federation import relay

    virtual_room = await relay.join(
        peer_ip        = body.peer_ip,
        peer_port      = body.peer_port,
        remote_room_id = remote_room_id,
        remote_jwt     = remote_jwt,
        room_name      = room_info.get("name", "Remote Room"),
        invite_code    = body.invite_code.upper(),
        is_private     = room_info.get("is_private", False),
        member_count   = room_info.get("member_count", 0),
        user_id        = u.id,
    )

    logger.info(
        f"🌐 {u.username} → {body.peer_ip}:{body.peer_port}/room/{remote_room_id} "
        f"(virtual_id={virtual_room.virtual_id})"
    )

    return {
        "joined":       True,
        "is_federated": True,
        "ws_path":      f"/ws/fed/{virtual_room.virtual_id}",
        "room": {
            "id":           virtual_room.virtual_id,
            "name":         virtual_room.room_name,
            "description":  f"🌐 {body.peer_ip}:{body.peer_port}",
            "is_private":   virtual_room.is_private,
            "invite_code":  virtual_room.invite_code,
            "member_count": virtual_room.member_count,
            "online_count": 0,
            "created_at":   "",
            "is_federated": True,
            "peer_ip":      body.peer_ip,
            "peer_port":    body.peer_port,
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# Multihop join (A → B → C)
# ══════════════════════════════════════════════════════════════════════════════

class MultihopJoinRequest(BaseModel):
    invite_code: str
    target_ip:   str
    target_port: int
    via_ip:      str
    via_port:    int


@router.post("/multihop-join")
async def multihop_join(
        body:    MultihopJoinRequest,
        u:       User    = Depends(get_current_user),
):
    """
    Мультихоп A → B → C.
    A не может достучаться до C напрямую.
    A авторизуется на B и просит его сделать federated-join к C.
    Итог: два relay-соединения A↔B↔C.
    """
    via_base = None
    for scheme in ("https", "http"):
        try:
            r = await _federation_pool.get(
                f"{scheme}://{body.via_ip}:{body.via_port}/api/peers/status"
            )
            if r.status_code == 200:
                via_base = f"{scheme}://{body.via_ip}:{body.via_port}"
                break
        except Exception:
            continue

    if not via_base:
        raise HTTPException(503, f"Intermediate node {body.via_ip} is unreachable")

    # ── Cached guest-login JWT on via-node ──────────────────────────────
    via_cache_key = f"{via_base}:{u.username}"
    via_cached = _jwt_cache.get(via_cache_key)
    if via_cached and via_cached["expires"] > time.monotonic():
        via_jwt = via_cached["jwt"]
    else:
        try:
            gr = await _federation_pool.post(
                f"{via_base}/api/federation/guest-login",
                json={
                    "username":      u.username,
                    "display_name":  u.display_name,
                    "avatar_emoji":  u.avatar_emoji,
                    "x25519_pubkey": u.x25519_public_key or "",
                    "peer_port":     Config.PORT,
                },
            )
        except Exception as e:
            raise HTTPException(502, f"guest-login on B ({body.via_ip}) failed: {e}")

        if gr.status_code != 200:
            raise HTTPException(502, f"guest-login on B: {gr.status_code}")

        via_jwt = gr.json()["access_token"]
        _jwt_cache[via_cache_key] = {"jwt": via_jwt, "expires": time.monotonic() + _JWT_CACHE_TTL}

    try:
        hr = await _federation_pool.post(
            f"{via_base}/api/peers/federated-join",
            headers={"Authorization": f"Bearer {via_jwt}"},
            json={
                "invite_code": body.invite_code,
                "peer_ip":     body.target_ip,
                "peer_port":   body.target_port,
            },
        )
    except Exception as e:
        raise HTTPException(502, f"federated-join B→C failed: {e}")

    if hr.status_code != 200:
        raise HTTPException(502, f"B→C join: {hr.status_code} {hr.text[:200]}")

    hop_data    = hr.json()
    via_room_id = hop_data["room"]["id"]

    from app.federation.federation import relay

    virtual_room = await relay.join(
        peer_ip        = body.via_ip,
        peer_port      = body.via_port,
        remote_room_id = via_room_id,
        remote_jwt     = via_jwt,
        room_name      = hop_data["room"].get("name", f"Room@{body.target_ip}"),
        invite_code    = body.invite_code.upper(),
        is_private     = hop_data["room"].get("is_private", True),
        member_count   = hop_data["room"].get("member_count", 1),
        user_id        = u.id,
    )

    logger.info(
        f"🔀 Multihop: {u.username} → {body.via_ip} → {body.target_ip}/room/{body.invite_code} "
        f"(virtual_id={virtual_room.virtual_id}, hops=2)"
    )

    return {
        "joined":       True,
        "is_federated": True,
        "hops":         2,
        "ws_path":      f"/ws/fed/{virtual_room.virtual_id}",
        "room": {
            "id":           virtual_room.virtual_id,
            "name":         virtual_room.room_name,
            "description":  f"🌐 {body.target_ip} via {body.via_ip}",
            "is_private":   virtual_room.is_private,
            "invite_code":  virtual_room.invite_code,
            "member_count": virtual_room.member_count,
            "online_count": 0,
            "created_at":   "",
            "is_federated": True,
            "peer_ip":      body.target_ip,
            "peer_port":    body.target_port,
            "hop_via":      body.via_ip,
            "hop_count":    2,
        },
    }

"""
API endpoints for pluggable transports, bridges, steganography, and tunnel.
"""
from __future__ import annotations

import base64
import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from app.security.auth_jwt import get_current_user
from app.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/transport", tags=["transport"])


# ── Pydantic models ──────────────────────────────────────────────────────────

class BridgeAddRequest(BaseModel):
    bridge_line: str  # "bridge 1.2.3.4:9000 abcdef1234567890"


class BridgeRegisterRequest(BaseModel):
    ip: str
    port: int
    pubkey_hex: str


class TunnelSendRequest(BaseModel):
    session_id: str
    data_b64: str


class StegoSendRequest(BaseModel):
    room_id: int
    data_b64: str
    width: int = 640
    height: int = 480


# ── Transport status ─────────────────────────────────────────────────────────

@router.get("/status")
async def transport_status(u: User = Depends(get_current_user)):
    """List all available transports and their status."""
    from app.transport.pluggable import transport_manager
    return transport_manager.get_status()


@router.get("/stealth-status")
async def stealth_status(u: User = Depends(get_current_user)):
    """Full stealth/obfuscation status — all mechanisms (Level 1-4)."""
    from app.transport.auto_stealth import get_stealth_status
    from app.transport.advanced_stealth import advanced_stealth
    from app.transport.stealth_level3 import stealth_l3
    from app.transport.stealth_level4 import stealth_l4
    base = get_stealth_status()
    base["advanced"] = advanced_stealth.get_status()
    base["level3"] = stealth_l3.get_status()
    base["level4"] = stealth_l4.get_status()
    return base


@router.post("/censorship-report")
async def censorship_report(request: Request):
    """
    Клиент отправляет отчёт о доступности транспортов.
    Без аутентификации (клиент может быть заблокирован).
    """
    from app.transport.stealth_level4 import stealth_l4
    try:
        body = await request.json()
        region = body.get("region", "unknown")
        stealth_l4.dashboard.submit_report(region, body)
        recommended = stealth_l4.dashboard.get_recommended_transport(region)
        return {"ok": True, "recommended_transport": recommended}
    except Exception:
        return {"ok": False}


@router.get("/censorship-map")
async def censorship_map(u: User = Depends(get_current_user)):
    """Карта блокировок по регионам."""
    from app.transport.stealth_level4 import stealth_l4
    return stealth_l4.dashboard.get_all_regions()


@router.get("/sw-config")
async def sw_config():
    """Конфигурация для Service Worker proxy (без авторизации)."""
    from app.transport.stealth_level4 import stealth_l4
    return stealth_l4.sw_config.generate_sw_config(
        transports=["websocket", "sse", "cdn_relay", "meek", "doh"],
    )


@router.get("/probe/{transport_name}")
async def probe_transport(transport_name: str):
    """Probe endpoint для проверки доступности транспорта."""
    return {"ok": True, "transport": transport_name, "ts": int(time.time())}


@router.get("/knock-hint")
async def knock_hint():
    """
    Замаскировано как /api/transport/knock-hint → feature flags.
    Клиент получает текущую knock-последовательность.
    Без аутентификации (клиент ещё не авторизован).
    """
    from app.transport.auto_stealth import get_knock_hint
    return get_knock_hint()


# ── Bridge endpoints ─────────────────────────────────────────────────────────

@router.post("/bridge/add")
async def add_bridge(body: BridgeAddRequest, u: User = Depends(get_current_user)):
    """Add a bridge by bridge line (shared privately by bridge operator)."""
    from app.transport.pluggable import bridge_registry
    parsed = bridge_registry.parse_bridge_line(body.bridge_line)
    if not parsed:
        raise HTTPException(400, "Invalid bridge line format. Expected: bridge <ip>:<port> <pubkey>")
    bid = bridge_registry.register_bridge(parsed["ip"], parsed["port"], parsed.get("pubkey_prefix", ""))
    return {"ok": True, "bridge_id": bid}


@router.post("/bridge/register")
async def register_bridge(body: BridgeRegisterRequest, u: User = Depends(get_current_user)):
    """Register this node or a known relay as a bridge."""
    from app.transport.pluggable import bridge_registry
    bid = bridge_registry.register_bridge(body.ip, body.port, body.pubkey_hex)
    line = bridge_registry.generate_bridge_line(body.ip, body.port, body.pubkey_hex)
    return {"ok": True, "bridge_id": bid, "bridge_line": line}


@router.get("/bridge/list")
async def list_bridges(u: User = Depends(get_current_user)):
    """List all known bridge nodes."""
    from app.transport.pluggable import bridge_registry
    return {"bridges": bridge_registry.list_bridges()}


@router.delete("/bridge/{bridge_id}")
async def remove_bridge(bridge_id: str, u: User = Depends(get_current_user)):
    """Remove a bridge."""
    from app.transport.pluggable import bridge_registry
    ok = bridge_registry.remove_bridge(bridge_id)
    if not ok:
        raise HTTPException(404, "Bridge not found")
    return {"ok": True}


@router.post("/bridge/enable")
async def enable_bridge_mode(u: User = Depends(get_current_user)):
    """Enable this node as a bridge relay for censored users."""
    from app.transport.pluggable import bridge_registry
    bridge_registry.enable_bridge_mode()
    return {"ok": True, "message": "This node is now a bridge relay"}


# ── TLS-in-TLS Tunnel ────────────────────────────────────────────────────────

@router.post("/tunnel/create")
async def create_tunnel(u: User = Depends(get_current_user)):
    """Create a new TLS tunnel session (WebSocket alternative)."""
    from app.transport.pluggable import tunnel
    session_id = tunnel.create_session()
    return {"session_id": session_id}


@router.post("/tunnel/send")
async def tunnel_send(body: TunnelSendRequest, u: User = Depends(get_current_user)):
    """Send data through tunnel (client → server)."""
    from app.transport.pluggable import tunnel
    data = base64.b64decode(body.data_b64)
    # Process the data as if it came from WebSocket
    # Here we'd dispatch to chat handler, but for now just echo
    ok = await tunnel.send_to_session(body.session_id, data)
    if not ok:
        raise HTTPException(404, "Tunnel session not found or full")
    return {"ok": True}


@router.get("/tunnel/recv/{session_id}")
async def tunnel_recv(session_id: str, u: User = Depends(get_current_user)):
    """Receive data from tunnel (server → client). Long-poll with 30s timeout."""
    from app.transport.pluggable import tunnel
    data = await tunnel.recv_from_session(session_id, timeout=30.0)
    if data is None:
        return Response(status_code=204)
    return Response(
        content=base64.b64encode(data),
        media_type="application/octet-stream",
    )


@router.delete("/tunnel/{session_id}")
async def close_tunnel(session_id: str, u: User = Depends(get_current_user)):
    """Close a tunnel session."""
    from app.transport.pluggable import tunnel
    tunnel.close_session(session_id)
    return {"ok": True}


# ── Steganography ─────────────────────────────────────────────────────────────

@router.post("/stego/send")
async def stego_send(body: StegoSendRequest, u: User = Depends(get_current_user)):
    """Send data hidden in a PNG image via steganography."""
    try:
        from app.transport.steganography import embed_data, generate_cover_image
    except ImportError:
        raise HTTPException(501, "Steganography not available (PIL not installed)")

    data = base64.b64decode(body.data_b64)
    cover = generate_cover_image(body.width, body.height)
    stego_image = embed_data(cover, data)

    if stego_image is None:
        raise HTTPException(413, "Data too large for cover image")

    return Response(
        content=stego_image,
        media_type="image/png",
        headers={
            "Content-Disposition": f"inline; filename=photo_{body.room_id}.png",
            "X-Stego": "true",
        },
    )


@router.post("/stego/receive")
async def stego_receive(request: Request, u: User = Depends(get_current_user)):
    """Extract hidden data from a steganographic PNG image."""
    try:
        from app.transport.steganography import extract_data
    except ImportError:
        raise HTTPException(501, "Steganography not available")

    body = await request.body()
    data = extract_data(body)

    if data is None:
        raise HTTPException(400, "No hidden data found in image")

    return Response(
        content=base64.b64encode(data),
        media_type="application/octet-stream",
    )


# ── Shadowsocks proxy config ────────────────────────────────────────────────

@router.get("/shadowsocks/config")
async def shadowsocks_config(u: User = Depends(get_current_user)):
    """Get Shadowsocks client config for connecting through encrypted proxy."""
    from app.transport.pluggable import transport_manager
    if not transport_manager.shadowsocks:
        raise HTTPException(404, "Shadowsocks transport not configured")
    from app.config import Config
    return transport_manager.shadowsocks.generate_client_config(
        server_host=Config.HOST,
        server_port=Config.PORT,
    )


# ── Domain fronting config ───────────────────────────────────────────────────

@router.get("/domain-fronting/config")
async def domain_fronting_config(u: User = Depends(get_current_user)):
    """Get domain fronting config for client."""
    from app.transport.pluggable import transport_manager
    if not transport_manager.domain_fronting:
        raise HTTPException(404, "Domain fronting not configured (set CDN_RELAY_URL)")
    return transport_manager.domain_fronting.get_config()

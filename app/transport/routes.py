"""
app/transport/routes.py — REST API for transport management.

Endpoints:
  GET  /api/transport/status          — status of all transports
  POST /api/transport/signal          — accept ICE candidates (signaling for hole punch)
  POST /api/transport/punch/{peer_ip} — initiate NAT hole punch to a peer
  GET  /api/transport/ble/peers       — list of BLE peers
  GET  /api/transport/wifi-direct/peers — list of Wi-Fi Direct peers
  POST /api/transport/wifi-direct/connect — connect to a P2P peer
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from app.models import User
from app.security.auth_jwt import get_current_user
from app.transport.transport_manager import transport_manager
from app.transport.nat_traversal import signaling, hole_puncher, StunClient
from app.transport.ble_transport import ble_manager
from app.transport.wifi_direct import wifi_direct_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/transport", tags=["transport"])


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────────────────────────────────────

class SignalRequest(BaseModel):
    """Incoming ICE candidates from a peer (for NAT hole punch signaling)."""
    session_id: str
    role:       str        # "initiator" | "responder"
    candidates: list[dict]


class HolePunchRequest(BaseModel):
    peer_ip:   str
    peer_port: int = Field(default=8000, ge=1, le=65535)


class WifiDirectConnectRequest(BaseModel):
    peer_mac: str
    method:   str = "pbc"   # "pbc" | "pin"
    pin:      Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/status")
async def transport_status(u: User = Depends(get_current_user)):
    """
    Returns full status of all transport subsystems:
      - NAT: external IP (STUN), active hole punch sessions
      - BLE: availability, peer list, RSSI
      - Wi-Fi Direct: availability, interface, peers
    """
    return transport_manager.full_status()


@router.get("/status/public")
async def transport_status_public():
    """
    Public status without authentication.
    Used by other nodes to check available transports.
    """
    status = transport_manager.full_status()
    return {
        "external_ip":   status.get("external_ip"),
        "external_port": status.get("external_port"),
        "ble_available": status.get("ble", {}).get("available", False),
        "wifi_direct_available": status.get("wifi_direct", {}).get("available", False),
    }


@router.post("/signal")
async def receive_signal(body: SignalRequest):
    """
    Accepts ICE candidates from another node.

    This endpoint is called during the NAT hole punching process:
      Node A gathers candidates -> POST /api/transport/signal to Node B
      Node B gathers candidates -> POST /api/transport/signal to Node A
      Both run punch() simultaneously
    """
    transport_manager.accept_signal(
        session_id = body.session_id,
        role       = body.role,
        candidates = body.candidates,
    )
    return {"ok": True, "session_id": body.session_id}


@router.post("/punch")
async def initiate_hole_punch(
        body: HolePunchRequest,
        background_tasks: BackgroundTasks,
        u: User = Depends(get_current_user),
):
    """
    Initiates NAT hole punch to the specified peer.

    The process takes several seconds, so the status can be checked
    via GET /api/transport/status after completion.
    """
    background_tasks.add_task(
        transport_manager.initiate_hole_punch,
        peer_ip   = body.peer_ip,
        peer_port = body.peer_port,
    )
    return {
        "ok":      True,
        "message": f"Hole punch to {body.peer_ip}:{body.peer_port} started",
    }


@router.post("/punch/sync")
async def initiate_hole_punch_sync(
        body: HolePunchRequest,
        u: User = Depends(get_current_user),
):
    """
    Synchronous hole punch — waits for the result (up to 15 seconds).
    Convenient for UI: can show success/failure immediately.
    """
    success = await transport_manager.initiate_hole_punch(
        peer_ip   = body.peer_ip,
        peer_port = body.peer_port,
    )
    return {
        "success":   success,
        "peer_ip":   body.peer_ip,
        "transport": "udp_hole_punch" if success else "relay_fallback",
    }


# ─────────────────────────────────────────────────────────────────────────────
# BLE Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/ble/peers")
async def ble_peers(u: User = Depends(get_current_user)):
    """List of BLE peers with signal strength (RSSI)."""
    peers = ble_manager.get_peers()
    return {
        "available": ble_manager.available,
        "count":     len(peers),
        "peers":     [p.to_dict() for p in peers],
    }


@router.post("/ble/scan")
async def ble_scan_now(u: User = Depends(get_current_user)):
    """Force an immediate BLE scan."""
    if not ble_manager.available:
        raise HTTPException(503, "BLE is not available on this device")
    # Run an unscheduled scan
    await ble_manager._do_scan()
    return {"ok": True, "peers": len(ble_manager.get_peers())}


@router.post("/ble/send/{peer_address}")
async def ble_send_message(
        peer_address: str,
        payload: dict,
        u: User = Depends(get_current_user),
):
    """Send a message to a specific BLE peer (MAC address)."""
    if not ble_manager.available:
        raise HTTPException(503, "BLE is not available")

    ok = await ble_manager.send_message(peer_address, payload)
    if not ok:
        raise HTTPException(502, f"Failed to send via BLE to {peer_address}")
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
# Wi-Fi Direct Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/wifi-direct/peers")
async def wifi_direct_peers(u: User = Depends(get_current_user)):
    """List of discovered Wi-Fi Direct peers."""
    return wifi_direct_manager.status()


@router.post("/wifi-direct/connect")
async def wifi_direct_connect(
        body: WifiDirectConnectRequest,
        u: User = Depends(get_current_user),
):
    """
    Connect to a Wi-Fi Direct peer.

    PBC (Push Button): both sides must initiate the connection simultaneously.
    PIN: provide the peer's PIN code.
    """
    if not wifi_direct_manager.available:
        raise HTTPException(503, "Wi-Fi Direct is not available on this device")

    if body.method == "pin" and body.pin:
        # Linux PIN connect
        wpa = wifi_direct_manager._wpa
        if wpa:
            ok = await wpa.p2p_connect_pin(body.peer_mac, body.pin)
            return {"ok": ok, "method": "pin"}
    else:
        # PBC connect
        ip = await wifi_direct_manager.connect_pbc(body.peer_mac)
        if ip:
            return {"ok": True, "method": "pbc", "peer_ip": ip}
        raise HTTPException(502, f"P2P PBC connect to {body.peer_mac} failed")

    return {"ok": False}


@router.post("/wifi-direct/create-group")
async def wifi_direct_create_group(u: User = Depends(get_current_user)):
    """
    Create a Wi-Fi Direct group (this node becomes Group Owner).
    Other devices can connect without an access point.
    """
    if not wifi_direct_manager.available or not wifi_direct_manager._wpa:
        raise HTTPException(503, "Wi-Fi Direct is not available")

    iface = await wifi_direct_manager._wpa.p2p_group_add()
    if not iface:
        raise HTTPException(502, "Failed to create P2P group")

    ip = await wifi_direct_manager._wpa.get_p2p_ip(iface)
    return {
        "ok":        True,
        "interface": iface,
        "ip":        ip,
    }


# ─────────────────────────────────────────────────────────────────────────────
# STUN / NAT Info
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/nat/info")
async def nat_info(u: User = Depends(get_current_user)):
    """NAT info: external IP, port, active hole punch sessions."""
    # Fresh STUN request
    external = await StunClient.discover_external()

    return {
        "external_ip":       external[0] if external else transport_manager._external_ip,
        "external_port":     external[1] if external else transport_manager._external_port,
        "own_local_ip":      transport_manager._own_ip,
        "active_sessions":   len(hole_puncher._sessions),
        "sessions": {
            sid: {
                "connected":  sess.connected,
                "remote":     sess.remote_addr,
                "candidates": len(sess.local_cands),
            }
            for sid, sess in hole_puncher._sessions.items()
        },
    }


@router.post("/nat/refresh-stun")
async def refresh_stun(u: User = Depends(get_current_user)):
    """Force refresh external IP via STUN."""
    result = await StunClient.discover_external()
    if result:
        transport_manager._external_ip, transport_manager._external_port = result
        return {"ok": True, "external_ip": result[0], "external_port": result[1]}
    raise HTTPException(503, "STUN servers are unavailable")
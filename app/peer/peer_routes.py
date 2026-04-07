"""
app/peer/peer_routes.py — list_peers, peer_status, get_invite_qr, public-rooms, refresh-rooms.
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import Depends

from app.config import Config
from app.models import User
from app.peer._router import router
from app.peer.peer_discovery import _fetch_peer_rooms, _get_node_keys
from app.peer.peer_models import registry
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)


@router.get("")
async def list_peers(u: User = Depends(get_current_user)):
    peers = registry.active()
    return {
        "own_ip":    registry.own_ip,
        "count":     len(peers),
        "peers":     [p.to_dict() for p in peers],
        "encrypted": sum(1 for p in peers if p.has_encryption()),
    }


@router.get("/status")
async def peer_status():
    _, node_pub_raw = _get_node_keys()
    node_pub = node_pub_raw if isinstance(node_pub_raw, bytes) else bytes(node_pub_raw)
    return {"ok": True, "own_ip": registry.own_ip,
            "peers": len(registry.active()), "pubkey": node_pub.hex()}


@router.get("/invite-qr")
async def get_invite_qr():
    """
    Возвращает URL для приглашения на этот узел и QR-код в формате SVG.
    Любой человек, отсканировавший QR или перейдя по ссылке, попадёт на этот узел.
    """
    import io
    _, node_pub_raw = _get_node_keys()
    node_pub   = node_pub_raw if isinstance(node_pub_raw, bytes) else bytes(node_pub_raw)
    pubkey_hex = node_pub.hex()

    own_ip = registry.own_ip or "127.0.0.1"
    port   = Config.PORT
    proto  = "https" if getattr(Config, "SSL_ENABLED", False) else "http"

    node_url   = f"{proto}://{own_ip}:{port}"
    invite_url = f"{node_url}?pubkey={pubkey_hex}"

    qr_svg: str | None = None
    try:
        import qrcode
        import qrcode.image.svg

        qr = qrcode.QRCode(
            version         = None,
            error_correction= qrcode.constants.ERROR_CORRECT_M,
            box_size        = 8,
            border          = 3,
        )
        qr.add_data(invite_url)
        qr.make(fit=True)
        img = qr.make_image(image_factory=qrcode.image.svg.SvgFillImage)
        buf = io.BytesIO()
        img.save(buf)
        qr_svg = buf.getvalue().decode("utf-8")
    except Exception as _qr_err:
        logger.debug("QR generation error: %s", _qr_err)

    return {
        "node_url":   node_url,
        "invite_url": invite_url,
        "pubkey":     pubkey_hex,
        "qr_svg":     qr_svg,
    }


@router.get("/public-rooms")
async def get_peer_public_rooms(u: User = Depends(get_current_user)):
    return {"rooms": registry.get_all_peer_rooms(), "peers": len(registry.active())}


# Принудительно опрашивает всех известных активных пиров и обновляет кэш комнат.
# Вызывается клиентом перед чтением /public-rooms чтобы получить актуальный список.
@router.post("/refresh-rooms")
async def refresh_peer_rooms(u: User = Depends(get_current_user)):
    peers = registry.active()
    await asyncio.gather(*[_fetch_peer_rooms(p) for p in peers], return_exceptions=True)
    return {"refreshed": len(peers), "rooms": len(registry.get_all_peer_rooms())}

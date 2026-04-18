"""
app/peer/peer_p2p.py — P2P encrypted send/receive routes.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel

from app.config import Config
from app.models import User
from app.peer._router import router
from app.peer.connection_manager import manager as ws_manager
from app.peer.peer_discovery import _get_node_keys
from app.peer.peer_models import PeerInfo, registry
from app.security.auth_jwt import get_current_user
from app.security.ssl_context import make_peer_ssl_context

logger = logging.getLogger(__name__)

_peer_ssl_ctx = make_peer_ssl_context()


# ══════════════════════════════════════════════════════════════════════════════
# P2P encrypted send
# ══════════════════════════════════════════════════════════════════════════════

async def _send_to_peer_encrypted(
        peer:           PeerInfo,
        room_id:        int,
        sender:         str,
        ciphertext_hex: str,
        msg_type:       str = "text",
) -> bool:
    import httpx

    node_priv, node_pub_raw = _get_node_keys()
    node_pub        = node_pub_raw if isinstance(node_pub_raw, bytes) else bytes(node_pub_raw)
    node_priv_bytes = node_priv    if isinstance(node_priv,    bytes) else bytes(node_priv)

    payload_dict = {
        "room_id":    room_id,
        "sender":     sender,
        "ciphertext": ciphertext_hex,
        "msg_type":   msg_type,
    }

    try:
        if peer.has_encryption():
            from app.security.key_exchange import encrypt_p2p_payload
            encrypted    = encrypt_p2p_payload(payload_dict, node_priv_bytes, peer.node_pubkey_hex)
            request_body = {
                "ephemeral_pub": encrypted["ephemeral_pub"],
                "ciphertext":    encrypted["ciphertext"],
                "sender_pubkey": node_pub.hex(),
            }
        else:
            logger.warning(f"Peer {peer.ip} no pubkey — P2P unencrypted")
            request_body = {
                "plaintext_payload": payload_dict,
                "sender_pubkey":     node_pub.hex(),
            }

        async with httpx.AsyncClient(timeout=3.0, verify=_peer_ssl_ctx) as client:
            response = await client.post(
                f"{peer.base_url}/api/peers/receive",
                json=request_body,
            )
            return response.status_code == 200

    except Exception as e:
        logger.debug(f"P2P send to {peer.ip} failed: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# REST API — P2P receive / send
# ══════════════════════════════════════════════════════════════════════════════

class P2PReceiveRequest(BaseModel):
    ephemeral_pub:     Optional[str]  = None
    ciphertext:        Optional[str]  = None
    sender_pubkey:     Optional[str]  = None
    plaintext_payload: Optional[dict] = None


@router.post("/receive")
async def receive_from_peer(body: P2PReceiveRequest, request: Request):
    src_ip = request.client.host if request.client else "unknown"

    # Проверяем что отправитель — известный пир
    peer = registry.get(src_ip)
    if not peer and not body.ephemeral_pub:
        # Неизвестный пир без шифрования — отклоняем
        raise HTTPException(403, "Unknown node")

    if body.ephemeral_pub and body.ciphertext:
        node_priv_raw, _ = _get_node_keys()
        node_priv = node_priv_raw if isinstance(node_priv_raw, bytes) else bytes(node_priv_raw)
        try:
            from app.security.key_exchange import decrypt_p2p_payload
            msg = decrypt_p2p_payload(body.ephemeral_pub, body.ciphertext, node_priv)
        except Exception as e:
            logger.warning(f"P2P decrypt failed from {src_ip}: {e}")
            raise HTTPException(400, "Failed to decrypt P2P message")
    elif body.plaintext_payload:
        msg = body.plaintext_payload
    else:
        raise HTTPException(400, "Missing payload")

    if body.sender_pubkey:
        peer = registry.get(src_ip)
        if peer and peer.node_pubkey_hex and peer.node_pubkey_hex != body.sender_pubkey:
            logger.warning(f"P2P pubkey mismatch from {src_ip}")
        elif not peer:
            registry.update(src_ip, src_ip, Config.PORT, body.sender_pubkey)

    room_id        = msg.get("room_id")
    sender         = msg.get("sender", "unknown")
    ciphertext_hex = msg.get("ciphertext", "")
    msg_type       = msg.get("msg_type", "text")

    if not room_id:
        raise HTTPException(400, "Missing room_id in payload")

    await ws_manager.broadcast_to_room(room_id, {
        "type":       "peer_message",
        "sender":     sender,
        "sender_ip":  src_ip,
        "ciphertext": ciphertext_hex,
        "msg_type":   msg_type,
        "from_peer":  True,
    })
    return {"ok": True}


class SendReq(BaseModel):
    room_id:    int
    ciphertext: str
    msg_type:   str           = "text"
    peer_ip:    Optional[str] = None


@router.post("/send")
async def send_p2p(body: SendReq, u: User = Depends(get_current_user)):
    if body.peer_ip:
        peer = registry.get(body.peer_ip)
        if not peer:
            raise HTTPException(404, "Peer not found")
        ok = await _send_to_peer_encrypted(
            peer, body.room_id, u.username, body.ciphertext, body.msg_type
        )
        return {"sent": ok, "encrypted": peer.has_encryption()}

    peers   = registry.active()
    results = await asyncio.gather(
        *[_send_to_peer_encrypted(p, body.room_id, u.username, body.ciphertext, body.msg_type)
          for p in peers],
        return_exceptions=True,
    )
    return {
        "sent_to":         sum(1 for r in results if r is True),
        "total":           len(peers),
        "encrypted_peers": sum(1 for p in peers if p.has_encryption()),
    }

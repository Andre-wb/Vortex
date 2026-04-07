from __future__ import annotations

import os
from fastapi import APIRouter, Depends
from app.security.crypto import load_or_create_node_keypair
from app.security.auth_jwt import get_current_user
from app.models import User
from app.config import Config

router = APIRouter(prefix="/api/keys", tags=["keys"])


def _load_or_create_node_kyber(keys_dir) -> str | None:
    """Load or create a Kyber-768 keypair for this node. Returns public key hex or None."""
    import logging as _log
    _logger = _log.getLogger(__name__)
    kyber_pub_path = keys_dir / "kyber768_public.bin"
    kyber_sk_path = keys_dir / "kyber768_secret.bin"
    if kyber_pub_path.exists() and kyber_sk_path.exists():
        return kyber_pub_path.read_bytes().hex()
    try:
        from app.security.post_quantum import Kyber768, pq_available
        if not pq_available():
            return None
        k_pub, k_sk = Kyber768.keygen()
        kyber_pub_path.write_bytes(k_pub)
        kyber_sk_path.write_bytes(k_sk)
        os.chmod(kyber_sk_path, 0o600)
        _logger.info("Node Kyber-768 keypair generated")
        return k_pub.hex()
    except Exception as e:
        _logger.warning("Failed to generate node Kyber keypair: %s", e)
        return None


@router.get("/pubkey")
async def get_node_pubkey():
    """Возвращает X25519 и Kyber-768 публичные ключи этого узла."""
    _, node_pub_raw = load_or_create_node_keypair(Config.KEYS_DIR)
    node_pub = node_pub_raw if isinstance(node_pub_raw, bytes) else bytes(node_pub_raw)
    result = {"pubkey_hex": node_pub.hex()}
    kyber_hex = _load_or_create_node_kyber(Config.KEYS_DIR)
    if kyber_hex:
        result["kyber_pubkey_hex"] = kyber_hex
    return result


@router.get("/vapid-public")
async def get_vapid_public():
    """Returns VAPID public key for push subscription."""
    return {"vapid_public_key": Config.VAPID_PUBLIC_KEY}


@router.get("/ice-servers")
async def get_ice_servers(u: User = Depends(get_current_user)):
    """ICE/TURN конфигурация. Credentials из env vars, не из исходников."""
    turn_urls = os.getenv("TURN_URLS", "")
    turn_user = os.getenv("TURN_USERNAME", "")
    turn_cred = os.getenv("TURN_CREDENTIAL", "")

    servers = [{"urls": "stun:stun.l.google.com:19302"}]

    if turn_user and turn_cred:
        for url in turn_urls.split(","):
            url = url.strip()
            if url:
                servers.append({"urls": url, "username": turn_user, "credential": turn_cred})

    return {"ice_servers": servers}

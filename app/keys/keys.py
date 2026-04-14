from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import shutil
import subprocess
import time

from fastapi import APIRouter, Depends
from app.security.crypto import load_or_create_node_keypair
from app.security.auth_jwt import get_current_user
from app.models import User
from app.config import Config

router = APIRouter(prefix="/api/keys", tags=["keys"])
_logger = logging.getLogger(__name__)

# ── Self-hosted TURN (coturn) ────────────────────────────────────────────────

_TURN_SECRET = os.getenv("TURN_SECRET", "") or secrets.token_hex(32)
_TURN_PORT = int(os.getenv("TURN_PORT", "3478"))
_TURN_TLS_PORT = int(os.getenv("TURN_TLS_PORT", "5349"))
_TURN_REALM = os.getenv("TURN_REALM", "vortex")
_coturn_process = None
_coturn_available = None


def _detect_public_ip() -> str:
    """Detect the node's external IP for TURN candidates."""
    import socket
    # Try env first
    ip = os.getenv("PUBLIC_IP") or os.getenv("EXTERNAL_IP")
    if ip:
        return ip
    # Fallback: connect to external to discover local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _is_coturn_installed() -> bool:
    global _coturn_available
    if _coturn_available is not None:
        return _coturn_available
    _coturn_available = shutil.which("turnserver") is not None
    return _coturn_available


def start_coturn():
    """Start coturn as a subprocess if installed and not already running."""
    global _coturn_process
    if not _is_coturn_installed():
        _logger.info("coturn not installed — self-hosted TURN disabled")
        return False
    if _coturn_process and _coturn_process.poll() is None:
        return True  # already running

    ip = _detect_public_ip()
    _logger.info("Starting self-hosted coturn on %s:%d (secret-based auth)", ip, _TURN_PORT)

    try:
        _coturn_process = subprocess.Popen(
            [
                "turnserver",
                "--no-cli",
                "--no-tls",
                "--no-dtls",
                f"--listening-port={_TURN_PORT}",
                f"--realm={_TURN_REALM}",
                f"--static-auth-secret={_TURN_SECRET}",
                f"--external-ip={ip}",
                "--fingerprint",
                "--lt-cred-mech",
                "--use-auth-secret",
                "--min-port=49152",
                "--max-port=65535",
                "--log-file=/dev/null",
                "--pidfile=",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _logger.info("coturn started (pid=%d)", _coturn_process.pid)
        return True
    except Exception as e:
        _logger.warning("Failed to start coturn: %s", e)
        return False


def stop_coturn():
    global _coturn_process
    if _coturn_process:
        _coturn_process.terminate()
        try:
            _coturn_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _coturn_process.kill()
        _coturn_process = None


def _generate_turn_credentials(ttl: int = 86400) -> tuple[str, str]:
    """Generate time-limited TURN credentials (RFC 5766 long-term auth with shared secret)."""
    timestamp = int(time.time()) + ttl
    username = f"{timestamp}:vortex"
    password = hmac.new(
        _TURN_SECRET.encode(), username.encode(), hashlib.sha1
    ).digest()
    import base64
    return username, base64.b64encode(password).decode()


def _get_self_hosted_turn() -> list[dict] | None:
    """Return ICE server entries for the self-hosted coturn, or None if unavailable."""
    if not _is_coturn_installed():
        return None
    if _coturn_process is None or _coturn_process.poll() is not None:
        if not start_coturn():
            return None

    ip = _detect_public_ip()
    username, credential = _generate_turn_credentials()
    return [
        {"urls": f"turn:{ip}:{_TURN_PORT}", "username": username, "credential": credential},
        {"urls": f"turn:{ip}:{_TURN_PORT}?transport=tcp", "username": username, "credential": credential},
    ]


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
    """ICE/TURN конфигурация — децентрализованная: каждый Vortex-узел свой TURN."""
    turn_urls = os.getenv("TURN_URLS", "")
    turn_user = os.getenv("TURN_USERNAME", "")
    turn_cred = os.getenv("TURN_CREDENTIAL", "")

    from app.transport.stealth import get_stealth_ice_servers, is_stealth
    if is_stealth():
        servers = get_stealth_ice_servers()
    else:
        servers = [
            {"urls": "stun:stun.l.google.com:19302"},
            {"urls": "stun:stun1.l.google.com:19302"},
        ]

    # 1. User-configured TURN from env (highest priority)
    if turn_user and turn_cred:
        for url in turn_urls.split(","):
            url = url.strip()
            if url:
                servers.append({"urls": url, "username": turn_user, "credential": turn_cred})

    # 2. Self-hosted coturn on this Vortex node (decentralized — no external deps)
    if not turn_user:
        self_turn = _get_self_hosted_turn()
        if self_turn:
            servers.extend(self_turn)

    return {"ice_servers": servers}

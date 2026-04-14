"""
app/peer/peer_discovery.py — UDP discovery helpers & listeners/senders.
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import threading
import time
from typing import Optional

import httpx

from app.config import Config
from app.peer.peer_models import PeerInfo, registry, _main_loop
from app.security.ssl_context import make_peer_ssl_context
import app.peer.peer_models as _models

logger = logging.getLogger(__name__)

_peer_ssl_ctx = make_peer_ssl_context()


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _local_ip() -> str:
    for target in ("192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.05)
                s.connect((target, 80))
                ip = s.getsockname()[0]
                if not ip.startswith("127."):
                    return ip
        except Exception as e:
            logger.debug("Local IP probe via %s failed: %s", target, e)
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if not ip.startswith("127."):
            return ip
    except Exception as e:
        logger.debug("Local IP via hostname failed: %s", e)
    logger.warning("Could not detect local IP, falling back to 127.0.0.1")
    return "127.0.0.1"


def _subnet_broadcast(ip: str) -> str:
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.255"
    except Exception as e:
        logger.debug("Subnet broadcast calc failed for ip=%s: %s", ip, e)
    return "255.255.255.255"


def _get_node_keys():
    from app.security.crypto import load_or_create_node_keypair
    return load_or_create_node_keypair(Config.KEYS_DIR)


# ══════════════════════════════════════════════════════════════════════════════
# Room fetching
# ══════════════════════════════════════════════════════════════════════════════

async def _fetch_peer_rooms(peer: PeerInfo) -> None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{peer.ip}:{peer.port}/api/rooms/public"
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=_peer_ssl_ctx) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    rooms = resp.json().get("rooms", [])
                    registry.set_peer_rooms(peer.ip, rooms)
                    logger.info(
                        f"📦 {len(rooms)} public rooms from {peer.name}@{peer.ip} via {scheme}"
                    )
                    return
        except Exception as e:
            logger.debug(f"Failed {scheme}://{peer.ip}: {e}")


def _schedule_fetch_peer_rooms(peer: PeerInfo) -> None:
    loop = _models._main_loop
    if loop is not None and loop.is_running():
        asyncio.run_coroutine_threadsafe(_fetch_peer_rooms(peer), loop)
    else:
        logger.debug(f"_main_loop not ready, skip room fetch for {peer.ip}")


# ══════════════════════════════════════════════════════════════════════════════
# Discovery
# ══════════════════════════════════════════════════════════════════════════════

def start_discovery(device_name: str = "") -> None:
    try:
        _models._main_loop = asyncio.get_running_loop()
    except RuntimeError:
        _models._main_loop = asyncio.get_event_loop()

    name = device_name or socket.gethostname()
    registry.own_ip = _local_ip()

    # В глобальном режиме UDP discovery не нужен — используется gossip-протокол
    if Config.NETWORK_MODE == "global":
        logger.info("🌐 Global mode: UDP discovery отключён, используется gossip-протокол")
        return

    try:
        _, node_pub = _get_node_keys()
        node_pubkey_hex = node_pub.hex() if isinstance(node_pub, bytes) else bytes(node_pub).hex()
    except Exception as e:
        logger.warning(f"Не удалось получить X25519 ключ: {e}")
        node_pubkey_hex = None

    try:
        import vortex_chat as _vc
        _vc.start_discovery(name, Config.PORT)
        logger.info(f"🦀 Rust UDP discovery: «{name}»")

        def _sync_rust_peers():
            while True:
                try:
                    for ip, port in _vc.get_peers():
                        is_new = registry.update(ip, ip, port)
                        if is_new:
                            peer = registry.get(ip)
                            if peer:
                                _schedule_fetch_peer_rooms(peer)
                        else:
                            # Пир уже известен — всё равно обновляем его комнаты,
                            # чтобы подхватывать новые комнаты созданные после discovery.
                            peer = registry.get(ip)
                            if peer:
                                _schedule_fetch_peer_rooms(peer)
                except Exception:
                    pass
                time.sleep(3)

        threading.Thread(target=_sync_rust_peers, daemon=True, name="rust-peers-sync").start()
        return
    except (ImportError, AttributeError):
        logger.info("Python UDP discovery fallback")

    threading.Thread(target=_py_listener, daemon=True, name="udp-listen").start()
    threading.Thread(
        target=_py_sender, args=(name, node_pubkey_hex), daemon=True, name="udp-send"
    ).start()
    logger.info(f"🐍 Python UDP discovery: «{name}» pubkey={'yes' if node_pubkey_hex else 'no'}")


def _py_listener():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", Config.UDP_PORT))
        sock.settimeout(2.0)
    except OSError as e:
        logger.error(f"UDP bind failed: {e}")
        return

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            src_ip = addr[0]
            if src_ip == registry.own_ip or src_ip.startswith("127."):
                continue

            # Stealth mode: try to decrypt UDP broadcast
            from app.transport.stealth import is_stealth, decrypt_udp_broadcast
            if is_stealth():
                decrypted = decrypt_udp_broadcast(data)
                if decrypted:
                    data = decrypted

            info   = json.loads(data.decode())
            pubkey = info.get("pubkey")
            if pubkey and len(pubkey) != 64:
                pubkey = None
            if pubkey:
                try:
                    bytes.fromhex(pubkey)
                except ValueError:
                    pubkey = None

            is_new = registry.update(
                src_ip,
                str(info.get("name", src_ip))[:64],
                int(info.get("port", Config.PORT)),
                pubkey,
            )

            peer = registry.get(src_ip)
            if peer:
                if is_new:
                    # Новый пир — сразу забираем его комнаты.
                    _schedule_fetch_peer_rooms(peer)
                else:
                    # Известный пир прислал heartbeat — обновляем список его комнат,
                    # чтобы новые комнаты появлялись у соседей без перезапуска.
                    _schedule_fetch_peer_rooms(peer)

        except socket.timeout:
            registry.cleanup()
        except Exception as e:
            logger.warning(f"UDP listener error: {e}", exc_info=True)


def _py_sender(name: str, node_pubkey_hex: Optional[str]):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        try:
            own_ip = _local_ip()
            if own_ip != registry.own_ip and not own_ip.startswith("127."):
                registry.own_ip = own_ip

            payload_dict = {"name": name, "port": Config.PORT}
            if node_pubkey_hex:
                payload_dict["pubkey"] = node_pubkey_hex

            payload = json.dumps(payload_dict).encode()

            # Stealth mode: encrypt UDP broadcast
            from app.transport.stealth import is_stealth, encrypt_udp_broadcast, get_stealth_udp_port
            if is_stealth():
                payload = encrypt_udp_broadcast(payload)
            udp_port = get_stealth_udp_port() if is_stealth() else Config.UDP_PORT

            bcast   = _subnet_broadcast(own_ip)
            sock.sendto(payload, (bcast, udp_port))
            try:
                sock.sendto(payload, ("255.255.255.255", udp_port))
            except Exception:
                pass
        except Exception as e:
            logger.debug(f"UDP send: {e}")
        time.sleep(Config.UDP_INTERVAL_SEC)

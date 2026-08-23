"""
app/peer/peer_discovery.py — точка входа UDP-обнаружения узлов.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import threading
import time

import httpx

import app.peer.peer_models as _models
from app.config import Config
from app.peer.peer_models import PeerInfo, registry
from app.security.ssl_context import make_peer_ssl_context
from app.transport.stealth import is_stealth

logger = logging.getLogger(__name__)

_peer_ssl_ctx = make_peer_ssl_context()

ROOMS_FETCH_INTERVAL_SEC = 3

_BUILD_HINT = (
    "Модуль vortex_chat не установлен. Соберите расширение:\n"
    "    make rust-build\n"
    "или вручную:\n"
    "    maturin develop --release -m rust_utils/Cargo.toml"
)

try:
    import vortex_chat as _vc
except ImportError as exc:  # pragma: no cover - зависит от окружения сборки
    raise ImportError(_BUILD_HINT) from exc


def _get_node_keys():
    from app.security.crypto import load_or_create_node_keypair

    return load_or_create_node_keypair(Config.KEYS_DIR)


async def _fetch_peer_rooms(peer: PeerInfo) -> None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{peer.ip}:{peer.port}/api/rooms/public"
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=_peer_ssl_ctx) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    rooms = resp.json().get("rooms", [])
                    registry.set_peer_rooms(peer.ip, rooms)
                    logger.info(f"📦 {len(rooms)} public rooms from {peer.name}@{peer.ip} via {scheme}")
                    return
        except Exception as e:
            logger.debug(f"Failed {scheme}://{peer.ip}: {e}")


def _schedule_fetch_peer_rooms(peer: PeerInfo) -> None:
    loop = _models._main_loop
    if loop is not None and loop.is_running():
        asyncio.run_coroutine_threadsafe(_fetch_peer_rooms(peer), loop)
    else:
        logger.debug(f"_main_loop not ready, skip room fetch for {peer.ip}")


def start_discovery(device_name: str = "") -> None:
    try:
        _models._main_loop = asyncio.get_running_loop()
    except RuntimeError:
        _models._main_loop = asyncio.get_event_loop()

    name = device_name or socket.gethostname()

    if Config.NETWORK_MODE == "global":
        logger.info("🌐 Global mode: UDP discovery отключён, используется gossip-протокол")
        return

    try:
        _, node_pub = _get_node_keys()
        node_pubkey_hex = node_pub.hex() if isinstance(node_pub, bytes) else bytes(node_pub).hex()
    except Exception as e:
        logger.warning(f"Не удалось получить X25519 ключ: {e}")
        node_pubkey_hex = None

    _vc.start_discovery(
        name,
        Config.PORT,
        Config.UDP_PORT,
        float(Config.UDP_INTERVAL_SEC),
        float(Config.PEER_TIMEOUT_SEC),
        node_pubkey_hex,
        is_stealth(),
        Config.VORTEX_NETWORK_KEY.encode(),
    )
    logger.info(f"🦀 Rust UDP discovery: «{name}» pubkey={'yes' if node_pubkey_hex else 'no'}")

    threading.Thread(target=_fetch_rooms_of_peers, daemon=True, name="peer-rooms-fetch").start()


def _fetch_rooms_of_peers() -> None:
    """Опрашивает публичные комнаты соседей. Сам реестр ведёт Rust."""
    while True:
        with contextlib.suppress(Exception):
            registry.cleanup()
            for peer in registry.active():
                _schedule_fetch_peer_rooms(peer)
        time.sleep(ROOMS_FETCH_INTERVAL_SEC)

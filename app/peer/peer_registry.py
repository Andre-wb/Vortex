"""
P2P Discovery — UDP broadcast в локальной сети.
Если Rust скомпилирован: использует vortex_chat.start_discovery / get_peers.
Иначе: чистый Python fallback.
"""
from __future__ import annotations
import asyncio, json, logging, socket, threading, time
from dataclasses import dataclass, field
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.security.auth_jwt import get_current_user
from app.config import Config
from app.peer.connection_manager import manager as ws_manager
from app.models import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/peers", tags=["peers"])


@dataclass
class PeerInfo:
    name:      str
    ip:        str
    port:      int
    last_seen: float = field(default_factory=time.monotonic)

    def alive(self) -> bool:
        return (time.monotonic() - self.last_seen) < Config.PEER_TIMEOUT_SEC

    def to_dict(self) -> dict:
        return {
            "name": self.name, "ip": self.ip, "port": self.port,
            "age_sec": round(time.monotonic() - self.last_seen, 1),
            "online": self.alive(),
        }

    @property
    def base_url(self) -> str:
        return f"http://{self.ip}:{self.port}"


class PeerRegistry:
    """Python-side реестр пиров (используется и при Rust, и без него)."""

    def __init__(self):
        self._peers: dict[str, PeerInfo] = {}
        self._lock  = threading.Lock()
        self.own_ip: str = "127.0.0.1"

    def update(self, ip: str, name: str, port: int):
        with self._lock:
            if ip in self._peers:
                p = self._peers[ip]
                p.name, p.port, p.last_seen = name, port, time.monotonic()
            else:
                self._peers[ip] = PeerInfo(name=name, ip=ip, port=port)
                logger.info(f"🔍 New peer: {name} @ {ip}:{port}")

    def active(self) -> list[PeerInfo]:
        with self._lock:
            return [p for p in self._peers.values() if p.alive()]

    def get(self, ip: str) -> Optional[PeerInfo]:
        with self._lock:
            return self._peers.get(ip)

    def cleanup(self):
        with self._lock:
            dead = [ip for ip, p in self._peers.items() if not p.alive()]
            for ip in dead:
                del self._peers[ip]


registry = PeerRegistry()


# ══════════════════════════════════════════════════════════════════════════════
# Discovery запуск
# ══════════════════════════════════════════════════════════════════════════════

def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def start_discovery(device_name: str = "") -> None:
    """Запускает P2P discovery. Rust или Python fallback."""
    name = device_name or socket.gethostname()
    registry.own_ip = _local_ip()

    # Попытка использовать Rust discovery
    try:
        import vortex_chat as _vc
        _vc.start_discovery(name, Config.PORT)
        logger.info(f"🦀 Rust UDP discovery запущен как «{name}»")

        # Синхронизируем Rust peers в наш Python реестр
        def _sync_rust_peers():
            while True:
                try:
                    for ip, port in _vc.get_peers():
                        registry.update(ip, ip, port)
                except Exception:
                    pass
                time.sleep(3)

        threading.Thread(target=_sync_rust_peers, daemon=True, name="rust-peers-sync").start()
        return

    except (ImportError, AttributeError):
        logger.info("Python UDP discovery fallback")

    # Python fallback
    threading.Thread(target=_py_listener,  daemon=True, name="udp-listen").start()
    threading.Thread(target=_py_sender, args=(name,), daemon=True, name="udp-send").start()
    logger.info(f"🐍 Python UDP discovery запущен как «{name}»")


def _py_listener():
    own_ip = registry.own_ip
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
            src = addr[0]
            if src == own_ip:
                continue
            info = json.loads(data.decode())
            registry.update(src, str(info.get("name", src))[:64], int(info.get("port", Config.PORT)))
        except socket.timeout:
            registry.cleanup()
        except Exception as e:
            logger.debug(f"UDP recv: {e}")


def _py_sender(name: str):
    payload = json.dumps({"name": name, "port": Config.PORT}).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        try:
            sock.sendto(payload, ("255.255.255.255", Config.UDP_PORT))
        except Exception:
            pass
        time.sleep(Config.UDP_INTERVAL_SEC)


# ══════════════════════════════════════════════════════════════════════════════
# P2P HTTP — отправка сообщений между узлами
# ══════════════════════════════════════════════════════════════════════════════

async def _send_to_peer(peer: PeerInfo, room_id: int, sender: str, text: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.post(f"{peer.base_url}/api/peers/receive",
                             json={"room_id": room_id, "sender": sender, "text": text})
            return r.status_code == 200
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# REST API
# ══════════════════════════════════════════════════════════════════════════════

@router.get("")
async def list_peers(u: User = Depends(get_current_user)):
    peers = registry.active()
    return {"own_ip": registry.own_ip, "count": len(peers),
            "peers": [p.to_dict() for p in peers]}


@router.get("/status")
async def peer_status():
    """Публичный endpoint — для пинга с других узлов."""
    return {"ok": True, "own_ip": registry.own_ip,
            "peers": len(registry.active())}


class MsgIn(BaseModel):
    room_id: int
    sender:  str
    text:    str


@router.post("/receive")
async def receive_from_peer(msg: MsgIn, request: Request):
    """Принять P2P сообщение и раздать локальным WS клиентам."""
    src_ip = request.client.host if request.client else "unknown"
    peer   = registry.get(src_ip)
    if not peer:
        # Незарегистрированный пир — разрешаем, но предупреждаем
        logger.warning(f"P2P msg from unregistered peer {src_ip}")

    await ws_manager.broadcast_to_room(msg.room_id, {
        "type":      "peer_message",
        "sender":    msg.sender,
        "sender_ip": src_ip,
        "text":      msg.text,
        "from_peer": True,
    })
    return {"ok": True}


class SendReq(BaseModel):
    room_id:  int
    text:     str
    peer_ip:  Optional[str] = None


@router.post("/send")
async def send_p2p(body: SendReq, u: User = Depends(get_current_user)):
    if body.peer_ip:
        peer = registry.get(body.peer_ip)
        if not peer:
            raise HTTPException(404, "Пир не найден")
        ok = await _send_to_peer(peer, body.room_id, u.username, body.text)
        return {"sent": ok}

    peers   = registry.active()
    results = await asyncio.gather(
        *[_send_to_peer(p, body.room_id, u.username, body.text) for p in peers],
        return_exceptions=True,
    )
    return {"sent_to": sum(1 for r in results if r is True), "total": len(peers)}
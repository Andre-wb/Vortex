"""
app/transport/global_routes.py — API-эндпоинты для глобального режима (gossip, bootstrap, поиск).

Эти маршруты доступны только при NETWORK_MODE=global.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.config import Config
from app.models import User
from app.security.auth_jwt import get_current_user
from app.transport.global_transport import global_transport

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/global", tags=["global"])

# ── Per-IP rate limiter for gossip / bootstrap ────────────────────────────────
_gossip_rate: dict[str, list] = {}  # ip -> [timestamp, count]
GOSSIP_RATE_LIMIT = 10  # requests per minute


def _check_gossip_rate(ip: str) -> bool:
    """Return True if the request is within rate limits."""
    now = time.monotonic()
    bucket = _gossip_rate.get(ip)
    if bucket and now - bucket[0] < 60.0:
        bucket[1] += 1
        return bucket[1] <= GOSSIP_RATE_LIMIT
    _gossip_rate[ip] = [now, 1]
    return True


# ══════════════════════════════════════════════════════════════════════════════
# Pydantic-схемы
# ══════════════════════════════════════════════════════════════════════════════

class GossipRequest(BaseModel):
    """Входящий gossip-запрос: список пиров + комнат от другого узла."""
    sender_ip: str = Field(..., description="IP отправителя")
    sender_port: int = Field(..., description="Порт отправителя")
    sender_pubkey: str = Field("", description="X25519 pubkey отправителя (hex)")
    peers: list[dict] = Field(default_factory=list, max_length=500, description="Список пиров отправителя")
    rooms: list[dict] = Field(default_factory=list, max_length=1000, description="Публичные комнаты отправителя")


class BootstrapRequest(BaseModel):
    """Запрос на начальное подключение к сети."""
    sender_ip: str = Field(..., description="IP нового узла")
    sender_port: int = Field(..., description="Порт нового узла")
    sender_pubkey: str = Field("", description="X25519 pubkey нового узла (hex)")


class AddPeerRequest(BaseModel):
    """Ручное добавление пира (из QR-кода или ввода)."""
    ip: str = Field(..., description="IP пира")
    port: int = Field(9000, description="Порт пира")


# ══════════════════════════════════════════════════════════════════════════════
# Gossip-эндпоинт (принимает от любого узла без авторизации)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/gossip")
async def gossip(body: GossipRequest, request: Request):
    """
    Приём gossip-пакета от другого узла.
    Обмен списками пиров и комнат → формирование mesh-сети.
    Не требует аутентификации — это межузловой протокол.
    """
    # Per-IP rate limit
    client_ip = request.client.host if request.client else body.sender_ip
    if not _check_gossip_rate(client_ip):
        raise HTTPException(429, "Rate limit exceeded")

    # Валидация sender_pubkey — должен быть 64-символьный hex или пустая строка
    if body.sender_pubkey:
        if len(body.sender_pubkey) != 64:
            raise HTTPException(400, "Invalid sender pubkey length")
        try:
            bytes.fromhex(body.sender_pubkey)
        except ValueError:
            raise HTTPException(400, "Invalid pubkey hex")

    # Всегда используем реальный IP из TCP-соединения (защита от спуфинга)
    real_ip = request.client.host if request.client else body.sender_ip

    result = global_transport.handle_gossip(
        sender_ip=real_ip,
        sender_port=body.sender_port,
        sender_pubkey=body.sender_pubkey,
        peers=body.peers,
        rooms=body.rooms,
    )

    # Добавляем наши комнаты в ответ
    our_rooms = await global_transport._get_our_public_rooms()
    result["rooms"] = our_rooms

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Bootstrap-эндпоинт (начальное подключение)
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/bootstrap")
async def bootstrap(body: BootstrapRequest, request: Request):
    """
    Начальное подключение нового узла к mesh-сети.
    Возвращает информацию об узле + текущий список пиров.
    Не требует аутентификации.
    """
    # Per-IP rate limit
    client_ip = request.client.host if request.client else body.sender_ip
    if not _check_gossip_rate(client_ip):
        raise HTTPException(429, "Rate limit exceeded")

    # Валидация sender_pubkey — должен быть 64-символьный hex или пустая строка
    if body.sender_pubkey:
        if len(body.sender_pubkey) != 64:
            raise HTTPException(400, "Invalid sender pubkey length")
        try:
            bytes.fromhex(body.sender_pubkey)
        except ValueError:
            raise HTTPException(400, "Invalid pubkey hex")

    real_ip = body.sender_ip
    if request.client and request.client.host:
        client_ip = request.client.host
        if client_ip not in ("127.0.0.1", "0.0.0.0"):
            real_ip = client_ip

    result = global_transport.handle_bootstrap(
        sender_ip=real_ip,
        sender_port=body.sender_port,
        sender_pubkey=body.sender_pubkey,
    )

    # Добавляем наши публичные комнаты
    result["rooms"] = await global_transport._get_our_public_rooms()

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Поиск комнат
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/search-rooms")
async def search_rooms_local(q: str = Query("", description="Поисковый запрос")):
    """
    Поиск публичных комнат НА ЭТОМ узле по имени.
    Вызывается другими узлами через gossip-протокол.
    Не требует аутентификации — это межузловой запрос.
    """
    try:
        from app.database import SessionLocal
        from app.models_rooms import Room
        db = SessionLocal()
        try:
            query = db.query(Room).filter(Room.is_private == False)
            if q:
                query = query.filter(Room.name.ilike(f"%{q}%"))
            rooms = query.all()
            return {
                "rooms": [
                    {
                        "id": r.id,
                        "name": r.name,
                        "description": r.description or "",
                        "invite_code": r.invite_code,
                        "is_channel": getattr(r, "is_channel", False),
                        "is_voice": getattr(r, "is_voice", False),
                        "avatar_emoji": getattr(r, "avatar_emoji", "") or "",
                        "avatar_url": getattr(r, "avatar_url", "") or "",
                        "member_count": r.member_count() if callable(getattr(r, "member_count", None)) else 0,
                    }
                    for r in rooms
                ]
            }
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Ошибка поиска комнат: {e}")
        return {"rooms": []}


@router.get("/search-rooms-global")
async def search_rooms_global(
    q: str = Query("", description="Поисковый запрос"),
    u: User = Depends(get_current_user),
):
    """
    Глобальный поиск комнат по ВСЕМ известным пирам.
    Требует аутентификации — вызывается клиентом.
    """
    rooms = await global_transport.search_rooms(q)
    return {
        "rooms": rooms,
        "peers_searched": global_transport.peer_count(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Информация об узле
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/node-info")
async def node_info():
    """
    Публичная информация об этом узле.
    Используется для пинга и проверки доступности.
    Не требует аутентификации.
    """
    try:
        from app.security.crypto import load_or_create_node_keypair
        _, pub = load_or_create_node_keypair(Config.KEYS_DIR)
        pubkey = pub.hex() if isinstance(pub, bytes) else bytes(pub).hex()
    except Exception:
        pubkey = ""

    return {
        "version": "3.0.0",
        "network_mode": Config.NETWORK_MODE,
        "node_pubkey": pubkey,
        "peers": global_transport.peer_count(),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Управление пирами (требует аутентификации)
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/peers")
async def list_global_peers(u: User = Depends(get_current_user)):
    """Список всех известных глобальных пиров."""
    peers = global_transport.get_peers()
    return {
        "count": len(peers),
        "peers": [
            {
                "ip": p.ip,
                "port": p.port,
                "pubkey": p.node_pubkey_hex[:16] + "..." if p.node_pubkey_hex else None,
                "last_seen_ago": round((__import__("time").time() - p.last_seen), 1),
                "rooms_count": len(p.rooms),
                "alive": p.alive(),
            }
            for p in peers
        ],
    }


@router.get("/cdn-status")
async def cdn_status(u: User = Depends(get_current_user)):
    """Статус CDN relay (Multi-CDN failover)."""
    from app.transport.cdn_relay import cdn_config
    return cdn_config.get_status()


@router.post("/add-peer")
async def add_peer(body: AddPeerRequest, u: User = Depends(get_current_user)):
    """
    Ручное добавление пира (из QR-кода или ввода IP).
    Требует аутентификации.
    """
    ok = await global_transport.add_bootstrap_peer(body.ip, body.port)
    return {
        "ok": ok,
        "addr": f"{body.ip}:{body.port}",
        "total_peers": global_transport.peer_count(),
    }

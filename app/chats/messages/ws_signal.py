"""
app/chats/chat_ws_signal.py — WebRTC signalling WebSocket and global notifications WS.
Extracted from chat.py.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.chats.messages._router import router
from app.chats.messages.core import ws_origin_ok  # shared CSWSH guard
from app.database import get_db
from app.models_rooms import RoomMember
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_user_ws

logger = logging.getLogger(__name__)

# room_id → {sender_pseudo → WebSocket}
#
# Ключ — sealed-sender псевдоним, а НЕ user_id: наружу в поле "from" уходит
# именно он, и клиент возвращает его же в "to". Реестр обязан жить в том же
# пространстве идентификаторов, иначе адресная доставка не находит получателя
# и каждый offer/answer уходит широковещательно (ломает mesh-звонки).
_signal_rooms: dict[int, dict[str, WebSocket]] = {}

# Per-user signal rate limiter (token bucket)
_signal_rate: dict[int, list] = {}  # user_id -> [timestamp, count]
SIGNAL_RATE_LIMIT = 100  # messages per second


@router.websocket("/ws/signal/{room_id:int}")
async def ws_signal(
    websocket: WebSocket,
    room_id: int,
    token: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    DEPRECATED: WebRTC signalling now goes through BMP for zero metadata leakage.
    This endpoint is kept for backward compatibility with old clients.
    New clients use BMP fast-poll (500ms) for signal delivery.
    """
    import json as _json

    # reject cross-site WS origins (CSWSH) before any processing.
    if not ws_origin_ok(websocket):
        await websocket.accept()
        await websocket.close(code=4403)
        return

    from app.transport.knock import is_knock_required, verify_knock

    if is_knock_required():
        has_auth = bool(websocket.cookies.get("access_token"))
        if not has_auth:
            knock_token = websocket.query_params.get("knock") or websocket.cookies.get("_vk")
            if not verify_knock(knock_token):
                await websocket.close(code=1000)
                return

    raw_token = websocket.cookies.get("access_token") or token
    if not raw_token:
        await websocket.accept()
        await websocket.close(code=4401)
        return

    try:
        user = await get_user_ws(raw_token, db)
    except HTTPException:
        await websocket.accept()
        await websocket.close(code=4401)
        return

    # enforce room membership (mirrors core.py ws_chat gate).
    # Reject non-members / banned users on the signalling socket too.
    member = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == user.id,
            RoomMember.is_banned.is_(False),
        )
        .first()
    )
    if not member:
        await websocket.accept()
        await websocket.close(code=4403)
        return

    await websocket.accept()
    from app.security.sealed_sender import compute_sender_pseudo

    _user_pseudo = compute_sender_pseudo(room_id, user.id)
    _signal_rooms.setdefault(room_id, {})[_user_pseudo] = websocket
    logger.debug("Signal WS+ (sanitized)")

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = _json.loads(raw)
            except Exception as e:
                logger.debug("Signal WS: invalid JSON from user %s: %s", user.id, e)
                continue

            # Rate limit: drop messages if user exceeds SIGNAL_RATE_LIMIT/sec
            now = time.monotonic()
            bucket = _signal_rate.get(user.id)
            if bucket and now - bucket[0] < 1.0:
                bucket[1] += 1
                if bucket[1] > SIGNAL_RATE_LIMIT:
                    continue  # drop message silently
            else:
                _signal_rate[user.id] = [now, 1]

            msg["from"] = _user_pseudo
            msg["display_name"] = user.display_name or user.username
            msg["avatar_emoji"] = user.avatar_emoji or "\U0001f464"

            # Padding для anti-DPI (размер фрейма рандомизирован)
            import secrets as _sec

            msg["_p"] = _sec.token_urlsafe(32 + _sec.randbelow(225))

            target = msg.get("to")
            padded = _json.dumps(msg)
            if target and target in _signal_rooms.get(room_id, {}):
                try:
                    await _signal_rooms[room_id][target].send_text(padded)
                except Exception as e:
                    logger.debug("Signal: dead WS target room=%s: %s", room_id, e)
                    _signal_rooms[room_id].pop(target, None)
            elif target:
                logger.debug("Signal: unknown target in room=%s, dropping", room_id)
            else:
                for pseudo, ws in list(_signal_rooms.get(room_id, {}).items()):
                    if pseudo != _user_pseudo:
                        try:
                            await ws.send_text(padded)
                        except Exception as e:
                            logger.debug("Signal broadcast: dead WS room=%s: %s", room_id, e)
                            _signal_rooms[room_id].pop(pseudo, None)

    except WebSocketDisconnect:
        logger.debug("Signal WS disconnect user=%s room=%s", user.username, room_id)
    finally:
        room_dict = _signal_rooms.get(room_id, {})
        if room_dict.get(_user_pseudo) is websocket:
            room_dict.pop(_user_pseudo, None)
        if not room_dict and room_id in _signal_rooms:
            del _signal_rooms[room_id]


@router.websocket("/ws/notifications")
async def ws_notifications(
    websocket: WebSocket,
    token: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Глобальный WS для уведомлений.
    Клиент подключается один раз и получает уведомления о новых сообщениях
    в комнатах, к WS которых он сейчас не подключён.
    """
    # reject cross-site WS origins (CSWSH) before any processing.
    if not ws_origin_ok(websocket):
        await websocket.accept()
        await websocket.close(code=4403)
        return

    raw_token = websocket.cookies.get("access_token") or token
    if not raw_token:
        await websocket.accept()
        await websocket.close(code=4401)
        return

    try:
        user = await get_user_ws(raw_token, db)
    except HTTPException:
        await websocket.accept()
        await websocket.close(code=4401)
        return

    await manager.connect_global(user.id, websocket)
    logger.debug("Notifications WS+ user=%s", user.username)

    try:
        while True:
            data = await websocket.receive_json()
            if data.get("action") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        logger.debug("Notifications WS disconnect user=%s", user.username)
    except Exception as e:
        logger.warning("Notifications WS error user=%s: %s", user.username, e)
    finally:
        manager.disconnect_global(user.id)

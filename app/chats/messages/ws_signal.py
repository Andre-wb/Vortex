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
from app.database import get_db
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_user_ws

logger = logging.getLogger(__name__)

# room_id → {user_id → WebSocket}
_signal_rooms: dict[int, dict[int, WebSocket]] = {}

# Per-user signal rate limiter (token bucket)
_signal_rate: dict[int, list] = {}  # user_id -> [timestamp, count]
SIGNAL_RATE_LIMIT = 100  # messages per second


@router.websocket("/ws/signal/{room_id:int}")
async def ws_signal(
    websocket: WebSocket,
    room_id:   int,
    token:     Optional[str] = None,
    db:        Session = Depends(get_db),
):
    """WebRTC signalling relay — relays ICE/SDP between peers in a room."""
    import json as _json

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

    await websocket.accept()
    _signal_rooms.setdefault(room_id, {})[user.id] = websocket
    logger.debug("Signal WS+ user=%s room=%s", user.username, room_id)

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

            msg["from"]         = user.id
            msg["username"]     = user.username
            msg["display_name"] = user.display_name or user.username
            msg["avatar_emoji"] = user.avatar_emoji or "\U0001f464"
            msg["avatar_url"]   = user.avatar_url

            # Padding для anti-DPI (размер фрейма рандомизирован)
            import secrets as _sec
            msg["_p"] = _sec.token_urlsafe(32 + _sec.randbelow(225))

            target_uid = msg.get("to")
            padded = _json.dumps(msg)
            if target_uid and target_uid in _signal_rooms.get(room_id, {}):
                try:
                    await _signal_rooms[room_id][target_uid].send_text(padded)
                except Exception as e:
                    logger.debug("Signal: dead WS target=%s room=%s: %s", target_uid, room_id, e)
                    _signal_rooms[room_id].pop(target_uid, None)
            else:
                for uid, ws in list(_signal_rooms.get(room_id, {}).items()):
                    if uid != user.id:
                        try:
                            await ws.send_text(padded)
                        except Exception as e:
                            logger.debug("Signal broadcast: dead WS user=%s room=%s: %s", uid, room_id, e)
                            _signal_rooms[room_id].pop(uid, None)

    except WebSocketDisconnect:
        logger.debug("Signal WS disconnect user=%s room=%s", user.username, room_id)
    finally:
        room_dict = _signal_rooms.get(room_id, {})
        room_dict.pop(user.id, None)
        if not room_dict and room_id in _signal_rooms:
            del _signal_rooms[room_id]


@router.websocket("/ws/notifications")
async def ws_notifications(
    websocket: WebSocket,
    token:     Optional[str] = None,
    db:        Session       = Depends(get_db),
):
    """
    Глобальный WS для уведомлений.
    Клиент подключается один раз и получает уведомления о новых сообщениях
    в комнатах, к WS которых он сейчас не подключён.
    """
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

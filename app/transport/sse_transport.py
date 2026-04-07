"""
app/transport/sse_transport.py — SSE транспорт (альтернатива WebSocket).

Для DPI: WebSocket имеет характерный Upgrade request.
SSE (Server-Sent Events) + POST выглядит как обычный HTTP/2 трафик.

Как работает:
  GET  /api/stream/{room_id}  -> SSE stream (сервер -> клиент)
  POST /api/stream/{room_id}  -> отправка сообщения (клиент -> сервер)

Для DPI это выглядит как:
  - Долгий GET запрос (как загрузка большого файла или видео стрим)
  - Короткие POST запросы (как отправка форм)

Не содержит WebSocket Upgrade -> не детектируется как мессенджер.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import RoomMember
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(tags=["sse-transport"])


class SSEMessage(BaseModel):
    action: str
    data: dict = {}


@router.get("/api/stream/{room_id}")
async def sse_stream(
    room_id: int,
    request: Request,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    SSE endpoint — альтернатива WebSocket для получения сообщений.
    Выглядит как обычный HTTP GET с длинным ответом (видеостриминг).
    """
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
        RoomMember.is_banned == False,
    ).first()
    if not member:
        raise HTTPException(403, "Нет доступа")

    queue: asyncio.Queue = asyncio.Queue()

    # Регистрируем очередь в менеджере для получения сообщений
    sse_key = f"sse:{room_id}:{u.id}"
    manager._sse_queues[sse_key] = queue

    async def event_generator():
        try:
            # Начальное событие
            yield f"data: {json.dumps({'type': 'connected', 'room_id': room_id})}\n\n"

            while True:
                # Проверяем что клиент всё ещё подключён
                if await request.is_disconnected():
                    break

                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"data: {json.dumps(msg)}\n\n"
                except asyncio.TimeoutError:
                    # Keepalive comment (не событие — DPI не видит паттерн)
                    yield f": keepalive {asyncio.get_event_loop().time()}\n\n"
        finally:
            manager._sse_queues.pop(sse_key, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # nginx: не буферизировать
        },
    )


@router.post("/api/stream/{room_id}")
async def sse_send(
    room_id: int,
    body: SSEMessage,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    POST endpoint — отправка сообщения через SSE транспорт.
    Выглядит как обычная отправка формы.
    """
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == u.id,
        RoomMember.is_banned == False,
    ).first()
    if not member:
        raise HTTPException(403, "Нет доступа")

    # Отправляем в SSE очереди всех подписчиков этой комнаты
    payload = {**body.data, "type": body.action, "sender_id": u.id}

    if hasattr(manager, '_sse_queues'):
        prefix = f"sse:{room_id}:"
        for key, queue in list(manager._sse_queues.items()):
            if key.startswith(prefix):
                try:
                    await queue.put(payload)
                except Exception as e:
                    logger.debug("SSE queue put failed for key %s: %s", key, e)

    return {"ok": True}

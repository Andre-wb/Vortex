"""
app/transport/blind_mailbox.py — HTTP-слой Blind Mailbox Protocol (BMP).

Транспорт без метаданных: сервер не знает, кто с кем переписывается. Клиенты
выводят вращающиеся идентификаторы ящиков из общего секрета и мешают реальные
запросы с прикрытием, поэтому настоящие операции неотличимы от фальшивых.

Сам протокол исполняет Rust (`app.transport.bmp_backend`): хранилище, пределы,
частота запросов, деривация идентификаторов и уборка. Здесь остались только
маршруты FastAPI.

Маршруты:
  POST   /api/bmp/post/{mailbox_id}   — положить зашифрованное сообщение
  POST   /api/bmp/batch               — забрать несколько ящиков одним запросом
  POST   /api/bmp/fast-batch          — то же с повышенным лимитом (звонки)
  POST   /api/bmp/room-secret/{id}    — зарегистрировать секрет комнаты
  GET    /api/bmp/stats               — статистика хранилища
  DELETE /api/bmp/gc                  — ручная уборка просроченных сообщений
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.security.auth_jwt import get_current_user
from app.transport import bmp_backend as backend

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/bmp", tags=["blind-mailbox"])

_LIMITS = backend.LIMITS

compute_mailbox_id = backend.compute_mailbox_id
compute_mailbox_ids = backend.compute_mailbox_ids


def _client(request: Request) -> str:
    from app.security.ip_privacy import raw_ip_for_ratelimit

    return raw_ip_for_ratelimit(request)


def _refuse(rejection) -> None:
    raise HTTPException(rejection.status, rejection.detail)


class DepositRequest(BaseModel):
    ct: str = Field(
        ...,
        max_length=_LIMITS["max_ciphertext_chars"],
        description="Hex-encoded E2E encrypted message",
    )


class BatchRequest(BaseModel):
    ids: list[str] = Field(
        ...,
        min_length=1,
        max_length=_LIMITS["max_batch"],
        description="List of mailbox IDs to fetch",
    )
    since: float = Field(0, description="Fetch messages newer than this timestamp")


class BMPSecretRequest(BaseModel):
    secret: str = Field(
        ...,
        min_length=_LIMITS["secret_hex_len"],
        max_length=_LIMITS["secret_hex_len"],
        description="Hex-encoded 32-byte HKDF-derived BMP secret",
    )


@router.post("/post/{mailbox_id}")
async def bmp_deposit(mailbox_id: str, body: DepositRequest, request: Request):
    """
    Положить зашифрованное сообщение в анонимный ящик.

    Аутентификация не нужна — писать в любой ящик может кто угодно, сервер не
    знает ни автора, ни адресата. Ограничение — по адресу источника.
    """
    rejection = await asyncio.to_thread(backend.deposit, mailbox_id, body.ct, _client(request))
    if rejection is not None:
        _refuse(rejection)
    return {"ok": True}


@router.post("/batch")
async def bmp_batch(body: BatchRequest, request: Request):
    """
    Забрать сообщения из нескольких ящиков одним запросом.

    Клиент присылает смесь настоящих идентификаторов и прикрытия, различить их
    сервер не может. В ответе только непустые ящики.
    """
    batch = await asyncio.to_thread(
        backend.fetch_batch, body.ids, body.since, _client(request), False
    )
    if batch.rejection is not None:
        _refuse(batch.rejection)
    return {"mailboxes": batch.mailboxes, "_p": batch.padding}


@router.post("/fast-batch")
async def bmp_fast_batch(body: BatchRequest, request: Request):
    """Как `/batch`, но с повышенным лимитом — опрос раз в 500 мс при звонке."""
    batch = await asyncio.to_thread(
        backend.fetch_batch, body.ids, body.since, _client(request), True
    )
    if batch.rejection is not None:
        _refuse(batch.rejection)
    return {"mailboxes": batch.mailboxes, "_p": batch.padding}


@router.post("/room-secret/{room_id}")
async def register_room_secret(
    room_id: int,
    body: BMPSecretRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Зарегистрировать BMP-секрет комнаты.

    Клиент выводит его из ключа комнаты через HKDF(info="bmp-mailbox"). Сервер
    считает по нему идентификаторы ящиков для депозита и не может восстановить
    из него ключ комнаты.
    """
    from app.models_rooms import RoomMember

    member = (
        db.query(RoomMember)
        .filter(
            RoomMember.room_id == room_id,
            RoomMember.user_id == u.id,
            RoomMember.is_banned.is_(False),
        )
        .first()
    )
    if not member:
        raise HTTPException(403, "Not a member of this room")

    rejection = await asyncio.to_thread(backend.set_room_secret, room_id, body.secret)
    if rejection is not None:
        _refuse(rejection)
    logger.debug("[BMP] Room secret registered (sanitized)")
    return {"ok": True}


@router.get("/stats")
async def bmp_stats(u: User = Depends(get_current_user)):
    """Статистика хранилища BMP."""
    return await asyncio.to_thread(backend.stats)


@router.delete("/gc")
async def bmp_manual_gc(u: User = Depends(get_current_user)):
    """Убрать просроченные сообщения вручную."""
    removed = await asyncio.to_thread(backend.collect_garbage)
    stats = await asyncio.to_thread(backend.stats)
    return {"removed": removed, **stats}


async def deposit_envelope(room_id: int, envelope_hex: str) -> bool:
    """
    Положить зашифрованный конверт в ящики комнаты.

    Секрет комнаты берётся из хранилища, идентификаторы считаются на текущую и
    соседние эпохи (допуск на расхождение часов). Возвращает False, если секрет
    не зарегистрирован или хранилище отказало.
    """
    return await asyncio.to_thread(backend.deposit_envelope, room_id, envelope_hex)


async def start_bmp():
    """Подключить общее состояние и запустить фоновую уборку BMP."""
    await asyncio.to_thread(backend.use_shared_state)
    backend.start_garbage_collector()

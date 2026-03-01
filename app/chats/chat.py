"""
WebSocket чат, история, файлы, WebRTC сигнализация (X25519 handshake).
"""
from __future__ import annotations

import hashlib, json, logging, uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import (
    APIRouter, Depends, File, HTTPException, Query,
    Request, UploadFile, WebSocket, WebSocketDisconnect
)
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.security.auth_jwt import get_current_user, get_user_ws
from app.config import Config
from app.peer.connection_manager import manager
from app.security.crypto import (
    decrypt_message, encrypt_message, generate_key, hash_message,
    generate_x25519_keypair, derive_x25519_session_key,
    load_or_create_node_keypair,
)
from app.database import get_db
from app.models import User
from app.models_rooms import FileTransfer, Message, MessageType, Room, RoomMember

logger = logging.getLogger(__name__)
router = APIRouter(tags=["chats"])

UPLOAD_DIR = Config.UPLOAD_DIR
MAX_BYTES  = Config.MAX_FILE_BYTES

ALLOWED_MIME = {
    "image/jpeg", "image/png", "image/gif", "image/webp",
    "video/mp4", "video/webm",
    "audio/mpeg", "audio/ogg", "audio/wav", "audio/webm",
    "application/pdf", "text/plain",
    "application/zip", "application/octet-stream",
}

# WebRTC signal rooms: room_id → {user_id → WebSocket}
_signal_rooms: dict[int, dict[int, WebSocket]] = {}

# X25519 handshake sessions: ws_id → session data
_e2e_sessions: dict[str, dict] = {}


# ── helpers ──────────────────────────────────────────────────────────────────

def _require_member(room_id: int, user_id: int, db: Session) -> RoomMember:
    m = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user_id,
        RoomMember.is_banned == False,
        ).first()
    if not m:
        raise HTTPException(403, "Нет доступа к комнате")
    return m


def _get_room_key(room: Room, db: Session) -> bytes:
    if room.room_key and len(room.room_key) == 32:
        return bytes(room.room_key)
    k = generate_key()
    room.room_key = k
    db.commit()
    return k


def _msg_to_dict(msg: Message, text: Optional[str]) -> dict:
    return {
        "type": "message", "id": msg.id, "room_id": msg.room_id,
        "sender_id": msg.sender_id,
        "sender":       msg.sender.username    if msg.sender else "удалён",
        "display_name": msg.sender.display_name if msg.sender else "удалён",
        "avatar_emoji": msg.sender.avatar_emoji if msg.sender else "👤",
        "msg_type":     msg.msg_type.value,
        "text":         text,
        "file_name":    msg.file_name,
        "file_size":    msg.file_size,
        "reply_to_id":  msg.reply_to_id,
        "is_edited":    msg.is_edited,
        "created_at":   msg.created_at.isoformat(),
    }


def _decrypt_msg(msg: Message, room_key: bytes) -> Optional[str]:
    try:
        return decrypt_message(bytes(msg.content_encrypted), room_key).decode("utf-8", errors="replace")
    except Exception:
        return "[ошибка расшифровки]"


# ══════════════════════════════════════════════════════════════════════════════
# WebSocket Chat — /ws/{room_id}
# ══════════════════════════════════════════════════════════════════════════════

@router.websocket("/ws/{room_id}")
async def ws_chat(
        websocket: WebSocket, room_id: int,
        db: Session = Depends(get_db),
):
    # Аутентификация
    # БЫЛО: token читался из query-параметра ?token=...
    #       В JS: getCookie('access_token') возвращал null, потому что
    #       кука установлена с httponly=True — JavaScript её не видит.
    #       WebSocket-соединение САМО отправляет все куки в заголовке,
    #       поэтому токен надо читать из куки на стороне сервера.
    # СТАЛО: читаем access_token из httponly-куки websocket.cookies
    token = websocket.cookies.get("access_token")
    if not token:
        # Кука отсутствует — закрываем с кодом 4401 (не авторизован)
        await websocket.close(code=4401)
        return
    try:
        user = await get_user_ws(token, db)
    except Exception:
        await websocket.close(code=4401); return

    # Членство
    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user.id,
        RoomMember.is_banned == False,
        ).first()
    if not member:
        await websocket.close(code=4403); return

    await manager.connect(
        room_id, user.id, user.username,
        user.display_name or user.username,
        user.avatar_emoji or "👤", websocket,
        )

    # Online список
    await websocket.send_json({"type": "online", "users": manager.get_online_users(room_id)})

    # История (последние 60 сообщений)
    room = db.query(Room).filter(Room.id == room_id).first()
    rk   = _get_room_key(room, db)
    recent = (
        db.query(Message).filter(Message.room_id == room_id)
        .order_by(Message.created_at.desc()).limit(60).all()
    )
    recent.reverse()
    await websocket.send_json({
        "type": "history",
        "messages": [_msg_to_dict(m, _decrypt_msg(m, rk)) for m in recent],
    })

    # Публичный ключ этого узла (для E2E)
    _, node_pub = load_or_create_node_keypair(Config.KEYS_DIR)
    await websocket.send_json({
        "type": "node_pubkey",
        "pubkey_hex": node_pub.hex(),
    })

    # Основной цикл
    try:
        while True:
            raw  = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except Exception:
                continue

            action = data.get("action", "")

            if action == "ping":
                await websocket.send_json({"type": "pong"})

            elif action == "typing":
                await manager.set_typing(room_id, user.id, bool(data.get("is_typing")))

            elif action == "message":
                text = str(data.get("text", "")).strip()
                if not text or len(text) > 4000:
                    continue
                rk  = _get_room_key(room, db)
                enc = encrypt_message(text.encode(), rk)
                h   = hash_message(text.encode())
                msg = Message(
                    room_id=room_id, sender_id=user.id,
                    msg_type=MessageType.TEXT,
                    content_encrypted=enc, content_hash=h,
                    reply_to_id=data.get("reply_to_id"),
                )
                db.add(msg); db.commit(); db.refresh(msg)
                await manager.set_typing(room_id, user.id, False)
                await manager.broadcast_to_room(room_id, _msg_to_dict(msg, text))

    except WebSocketDisconnect:
        await manager.disconnect(room_id, user.id)
    except Exception as e:
        logger.error(f"WS error: {e}", exc_info=True)
        await manager.disconnect(room_id, user.id)


# ══════════════════════════════════════════════════════════════════════════════
# X25519 Key Exchange Endpoint
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/keys/pubkey")
async def get_pubkey(u: User = Depends(get_current_user)):
    """Возвращает X25519 публичный ключ этого узла."""
    _, pub = load_or_create_node_keypair(Config.KEYS_DIR)
    return {"pubkey_hex": pub.hex(), "algorithm": "X25519"}


@router.post("/api/keys/derive")
async def derive_key(peer_pubkey_hex: str, u: User = Depends(get_current_user)):
    """
    Деривация сессионного ключа: X25519(our_priv, peer_pub) → HKDF → AES key.
    Возвращает SHA-256 fingerprint ключа (не сам ключ!) для верификации.
    """
    try:
        peer_pub = bytes.fromhex(peer_pubkey_hex)
        if len(peer_pub) != 32:
            raise ValueError("Неверная длина ключа")
    except Exception:
        raise HTTPException(422, "Неверный формат публичного ключа (hex, 32 байта)")

    priv, _ = load_or_create_node_keypair(Config.KEYS_DIR)
    session_key = derive_x25519_session_key(priv, peer_pub)

    import hashlib
    fingerprint = hashlib.sha256(session_key).hexdigest()[:16]
    return {
        "fingerprint": fingerprint,
        "algorithm":   "X25519+HKDF-SHA256+AES-256-GCM",
        "key_bits":    256,
    }


# ══════════════════════════════════════════════════════════════════════════════
# История и онлайн
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/api/chats/{room_id}/history")
async def history(
        room_id: int,
        before_id: Optional[int] = Query(None),
        limit:     int           = Query(50, ge=1, le=200),
        u:    User    = Depends(get_current_user),
        db:   Session = Depends(get_db),
):
    _require_member(room_id, u.id, db)
    room = db.query(Room).filter(Room.id == room_id).first()
    rk   = _get_room_key(room, db)
    q    = db.query(Message).filter(Message.room_id == room_id)
    if before_id:
        q = q.filter(Message.id < before_id)
    msgs = q.order_by(Message.created_at.desc()).limit(limit).all()
    msgs.reverse()
    return {
        "messages": [_msg_to_dict(m, _decrypt_msg(m, rk)) for m in msgs],
        "has_more": len(msgs) == limit,
    }


@router.get("/api/chats/{room_id}/online")
async def online(room_id: int, u: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    _require_member(room_id, u.id, db)
    return {"users": manager.get_online_users(room_id)}


# ══════════════════════════════════════════════════════════════════════════════
# Файлы
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/api/files/upload/{room_id}", status_code=201)
async def upload_file(
        room_id: int, file: UploadFile = File(...),
        u: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    _require_member(room_id, u.id, db)
    if file.content_type and file.content_type not in ALLOWED_MIME:
        raise HTTPException(415, f"Тип файла не поддерживается: {file.content_type}")

    contents = await file.read()
    if len(contents) > MAX_BYTES:
        raise HTTPException(413, f"Файл > {Config.MAX_FILE_MB} МБ")

    room = db.query(Room).filter(Room.id == room_id).first()
    rk   = _get_room_key(room, db)

    encrypted  = encrypt_message(contents, rk)
    fhash      = hashlib.sha256(encrypted).hexdigest()
    stored_name = f"{uuid.uuid4().hex}_{room_id}"
    (UPLOAD_DIR / stored_name).write_bytes(encrypted)

    ft = FileTransfer(
        room_id=room_id, uploader_id=u.id,
        original_name=file.filename or "file",
        stored_name=stored_name, mime_type=file.content_type,
        size_bytes=len(contents), file_hash=fhash,
    )
    db.add(ft); db.flush()

    text_bytes = f"[file:{ft.id}:{file.filename}]".encode()
    msg = Message(
        room_id=room_id, sender_id=u.id,
        msg_type=MessageType.FILE,
        content_encrypted=encrypt_message(text_bytes, rk),
        content_hash=hash_message(text_bytes),
        file_name=file.filename, file_size=len(contents),
    )
    db.add(msg); db.commit()
    db.refresh(ft); db.refresh(msg)

    await manager.broadcast_to_room(room_id, {
        "type":         "file",
        "msg_id":       msg.id,    "file_id":    ft.id,
        "file_name":    ft.original_name,  "file_size": ft.size_bytes,
        "mime_type":    ft.mime_type,
        "sender":       u.username,
        "display_name": u.display_name or u.username,
        "avatar_emoji": u.avatar_emoji or "👤",
        "download_url": f"/api/files/download/{ft.id}",
        "created_at":   msg.created_at.isoformat(),
    })
    return {"file_id": ft.id, "download_url": f"/api/files/download/{ft.id}"}


@router.get("/api/files/download/{file_id}")
async def download_file(
        file_id: int, u: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    ft = db.query(FileTransfer).filter(
        FileTransfer.id == file_id, FileTransfer.is_available == True).first()
    if not ft:
        raise HTTPException(404)
    _require_member(ft.room_id, u.id, db)

    path = UPLOAD_DIR / ft.stored_name
    if not path.exists():
        raise HTTPException(404, "Файл не найден на диске")

    enc = path.read_bytes()

    # Целостность (SHA-256)
    if hashlib.sha256(enc).hexdigest() != ft.file_hash:
        logger.error(f"File integrity check FAILED: {ft.id}")
        raise HTTPException(500, "Нарушена целостность файла")

    room  = db.query(Room).filter(Room.id == ft.room_id).first()
    plain = decrypt_message(enc, bytes(room.room_key[:32]))
    ft.download_count += 1; db.commit()

    return StreamingResponse(
        iter([plain]),
        media_type=ft.mime_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{ft.original_name}"',
            "Content-Length": str(len(plain)),
        },
    )


@router.get("/api/files/room/{room_id}")
async def room_files(
        room_id: int, u: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    _require_member(room_id, u.id, db)
    files = (db.query(FileTransfer)
             .filter(FileTransfer.room_id == room_id, FileTransfer.is_available == True)
             .order_by(FileTransfer.created_at.desc()).limit(100).all())
    return {"files": [{
        "id": f.id, "file_name": f.original_name, "mime_type": f.mime_type,
        "size_bytes": f.size_bytes,
        "uploader": f.uploader.username if f.uploader else "—",
        "download_url": f"/api/files/download/{f.id}",
        "created_at": f.created_at.isoformat(),
    } for f in files]}


# ══════════════════════════════════════════════════════════════════════════════
# WebRTC Сигнализация — X25519 ключи + SDP exchange
# ══════════════════════════════════════════════════════════════════════════════

@router.websocket("/ws/signal/{room_id}")
async def signal_ws(
        websocket: WebSocket, room_id: int,
        db: Session = Depends(get_db),
):
    # Токен из httponly-куки (JS не может передать его через URL)
    token = websocket.cookies.get("access_token")
    if not token:
        await websocket.close(code=4401)
        return
    try:
        user = await get_user_ws(token, db)
    except Exception:
        await websocket.close(code=4401); return

    if not db.query(RoomMember).filter(
            RoomMember.room_id == room_id, RoomMember.user_id == user.id
    ).first():
        await websocket.close(code=4403); return

    await websocket.accept()

    if room_id not in _signal_rooms:
        _signal_rooms[room_id] = {}
    _signal_rooms[room_id][user.id] = websocket

    # Уведомляем остальных
    for uid, ws in list(_signal_rooms.get(room_id, {}).items()):
        if uid != user.id:
            try:
                await ws.send_json({
                    "type": "peer_joined", "from": user.id,
                    "username": user.username,
                    # Передаём X25519 pubkey для E2E ключа звонка
                    "x25519_pubkey": user.x25519_public_key,
                })
            except Exception:
                pass

    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type", "")
            if msg_type not in ("offer", "answer", "ice", "invite", "bye", "x25519_pubkey"):
                continue
            data["from"]     = user.id
            data["username"] = user.username
            to = data.get("to")
            if to:
                ws = _signal_rooms.get(room_id, {}).get(int(to))
                if ws:
                    try: await ws.send_json(data)
                    except Exception: pass
            else:
                for uid, ws in list(_signal_rooms.get(room_id, {}).items()):
                    if uid != user.id:
                        try: await ws.send_json(data)
                        except Exception: pass
    except WebSocketDisconnect:
        _signal_rooms.get(room_id, {}).pop(user.id, None)
        for uid, ws in list(_signal_rooms.get(room_id, {}).items()):
            try:
                await ws.send_json({"type": "peer_left", "from": user.id,
                                    "username": user.username})
            except Exception:
                pass
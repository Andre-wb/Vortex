"""
app/chats/chat_files.py — File upload, download, and room file listing.
Extracted from chat.py to keep it focused on WebSocket message handling.
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.chats.messages._router import router, utc_iso, check_double_extension
from app.config import Config
from app.database import get_db
from app.models import User
from app.models_rooms import FileTransfer, Message, MessageType, RoomMember
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user
from app.security.sealed_sender import compute_sender_pseudo
from app.security.secure_upload import (
    FileAnomalyDetector, FileUploadConfig,
    calculate_file_hash, generate_secure_filename,
    read_file_chunked, validate_file_mime_type,
    strip_exif, strip_all_metadata, generate_encrypted_thumbnail,
)

logger = logging.getLogger(__name__)


@router.post("/api/files/upload/{room_id}")
async def upload_file(
    room_id: int,
    request: Request,
    file:    UploadFile          = File(...),
    u:       User                = Depends(get_current_user),
    db:      Session             = Depends(get_db),
):
    """Upload a file to a room. Validates MIME type, extensions, and content."""
    if room_id < 0:
        from app.federation.federation import relay as _fed_relay
        _fed_info = _fed_relay.get_room(room_id)
        if not _fed_info or u.id not in _fed_info.local_user_ids:
            raise HTTPException(403, "Нет доступа к комнате")
    else:
        member = db.query(RoomMember).filter(
            RoomMember.room_id   == room_id,
            RoomMember.user_id   == u.id,
            RoomMember.is_banned == False,
        ).first()
        if not member:
            raise HTTPException(403, "Нет доступа к комнате")

    filename = file.filename or "file"

    try:
        content, size = await read_file_chunked(file, FileUploadConfig.MAX_FILE_SIZE)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Ошибка чтения файла: {e}")

    if FileAnomalyDetector.detect_null_bytes(filename):
        raise HTTPException(400, "Недопустимые символы в имени файла")
    if FileAnomalyDetector.detect_path_traversal(filename):
        raise HTTPException(400, "Недопустимое имя файла")
    if check_double_extension(filename):
        raise HTTPException(400, "Недопустимое расширение файла")
    if FileAnomalyDetector.detect_zip_bomb_indicators(content):
        raise HTTPException(400, "Файл имеет признаки архивной бомбы")

    mime_ok, mime_result = validate_file_mime_type(content, filename)
    if not mime_ok:
        raise HTTPException(415, mime_result or "Неподдерживаемый тип файла")
    mime_type = mime_result

    is_image = mime_type and mime_type.startswith("image/")
    if is_image:
        img_ok, img_err = await FileAnomalyDetector.validate_image_content(content)
        if not img_ok:
            raise HTTPException(400, img_err or "Неверное содержимое изображения")

    # Strip ALL metadata: images (EXIF/GPS), video (ffmpeg), audio (ID3), PDF (author/dates)
    content = strip_all_metadata(content, mime_type)
    size = len(content)

    ext       = Path(filename).suffix.lower()
    file_hash = calculate_file_hash(content)

    Config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe_name   = generate_secure_filename(ext)
    stored_path = Config.UPLOAD_DIR / safe_name
    stored_path.write_bytes(content)

    ft = FileTransfer(
        room_id       = room_id,
        uploader_id   = u.id,
        original_name = filename,
        stored_name   = safe_name,
        mime_type     = mime_type,
        size_bytes    = size,
        file_hash     = file_hash,
    )
    db.add(ft)
    db.commit()
    db.refresh(ft)

    download_url = f"/api/files/download/{ft.id}"

    is_voice = filename.startswith("voice_") and mime_type and mime_type.startswith("audio/")
    msg_type = MessageType.VOICE if is_voice else (MessageType.IMAGE if is_image else MessageType.FILE)

    placeholder_encrypted = b"\x00" * 12 + b"\x00" * 16
    msg = Message(
        room_id           = room_id,
        sender_pseudo     = compute_sender_pseudo(room_id, u.id),
        msg_type          = msg_type,
        content_encrypted = placeholder_encrypted,
        file_name         = filename,
        file_size         = size,
    )
    db.add(msg)
    db.commit()

    await manager.broadcast_to_room(room_id, {
        "type":         "file",
        "sender_pseudo": compute_sender_pseudo(room_id, u.id),
        "sender":       u.username,
        "display_name": u.display_name or u.username,
        "avatar_emoji": u.avatar_emoji,
        "avatar_url":   u.avatar_url,
        "file_name":    filename,
        "file_size":    size,
        "mime_type":    mime_type,
        "download_url": download_url,
        "msg_type":     msg_type.value,
        "created_at":   utc_iso(ft.created_at),
        "file_hash":    file_hash,
    })

    logger.info("File uploaded: %s (%d bytes) room=%d user=%s", filename, size, room_id, u.username)
    return {"ok": True, "file_id": ft.id, "download_url": download_url, "file_hash": file_hash}


@router.get("/api/files/download/{file_id}")
async def download_file(
    file_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    ft = db.query(FileTransfer).filter(
        FileTransfer.id           == file_id,
        FileTransfer.is_available == True,
    ).first()
    if not ft:
        raise HTTPException(404, "Файл не найден")

    member = db.query(RoomMember).filter(
        RoomMember.room_id   == ft.room_id,
        RoomMember.user_id   == u.id,
        RoomMember.is_banned == False,
    ).first()
    if not member:
        raise HTTPException(403, "Нет доступа")

    path = Config.UPLOAD_DIR / ft.stored_name
    if not path.exists():
        raise HTTPException(404, "Файл не найден на диске")

    ft.download_count += 1
    db.commit()

    return FileResponse(
        path       = str(path),
        filename   = ft.original_name,
        media_type = ft.mime_type or "application/octet-stream",
    )


@router.get("/api/files/room/{room_id}")
async def list_room_files(
    room_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    member = db.query(RoomMember).filter(
        RoomMember.room_id   == room_id,
        RoomMember.user_id   == u.id,
        RoomMember.is_banned == False,
    ).first()
    if not member:
        raise HTTPException(403, "Нет доступа")

    files = db.query(FileTransfer).filter(
        FileTransfer.room_id      == room_id,
        FileTransfer.is_available == True,
    ).order_by(FileTransfer.created_at.desc()).limit(100).all()

    return {"files": [
        {
            "id":           f.id,
            "file_name":    f.original_name,
            "mime_type":    f.mime_type,
            "size_bytes":   f.size_bytes,
            "file_hash":    f.file_hash,
            "uploader":     f.uploader.username if f.uploader else "—",
            "download_url": f"/api/files/download/{f.id}",
            "created_at":   utc_iso(f.created_at),
        }
        for f in files
    ]}

"""
app/files/resumable.py — Протокол возобновляемой загрузки файлов.

Архитектура:
  1. POST /api/files/upload-init          — инициализация сессии, возвращает upload_id
  2. PUT  /api/files/upload-chunk/{id}    — загрузка одного чанка (chunk_index, data, sha256)
  3. GET  /api/files/upload-status/{id}   — список полученных чанков (для возобновления)
  4. POST /api/files/upload-complete/{id} — сборка, проверка хеша, сохранение
  5. DELETE /api/files/upload-cancel/{id} — отмена сессии

Каждый чанк:
  - имеет порядковый номер (0-based)
  - сопровождается SHA-256 хешем для контроля целостности
  - хранится во временной директории до финальной сборки

Сессии живут в общем сторе (крейт vortex-resume, app/session/resume_backend.py)
плюс фоновая задача очистки протухших. Куски файла лежат на файловой системе
в TEMP_DIR/<upload_id>; путь выводится из upload_id, поэтому в сторе он не
хранится.

Подключение в main.py:
    from app.files.resumable import router as resumable_router, cleanup_sessions_loop
    app.include_router(resumable_router)

    # В lifespan:
    asyncio.create_task(cleanup_sessions_loop())
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import secrets
import shutil
from pathlib import Path

try:
    import vortex_chat as _vc_rust

    _HAS_RUST_SHA = hasattr(_vc_rust, "sha256_hex")
except ImportError:
    _HAS_RUST_SHA = False

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import Config
from app.database import get_db
from app.models import User
from app.models_rooms import FileTransfer, Message, MessageType, RoomMember
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user
from app.security.secure_upload import (
    FileAnomalyDetector,
    FileUploadConfig,
    generate_secure_filename,
    strip_all_metadata,
    validate_file_mime_type,
)
from app.session import resume_backend as _resume


def _sha256_hex(data: bytes) -> str:
    """Chunk-hash shortcut — picks Rust if available. 7× throughput win."""
    if _HAS_RUST_SHA:
        with contextlib.suppress(Exception):
            return _vc_rust.sha256_hex(data)
    return hashlib.sha256(data).hexdigest()


logger = logging.getLogger(__name__)
router = APIRouter(tags=["resumable-upload"])

DEFAULT_CHUNK_SIZE = _resume.upload_limits()["default_chunk_bytes"]
TEMP_DIR = Config.UPLOAD_DIR / "_chunks"

# web-shell / server-executable extensions, mirrors the direct path
# (app/chats/messages/_router.py DANGEROUS_EXTS). The chunked path previously
# skipped this check, accepting e.g. shell.php as the final extension.
WEBSHELL_EXTS = frozenset(
    {
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".phtml",
        ".asp",
        ".aspx",
        ".ascx",
        ".ashx",
        ".jsp",
        ".jspx",
        ".jws",
        ".exe",
        ".bat",
        ".cmd",
    }
)


# Доступ к сессиям загрузки


def _chunk_dir(upload_id: str) -> Path:
    return TEMP_DIR / upload_id


async def _discard_chunks(upload_id: str) -> None:
    """Удаляет временную директорию чанков сессии."""
    chunk_dir = _chunk_dir(upload_id)
    try:
        if chunk_dir.exists():
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: shutil.rmtree(chunk_dir, ignore_errors=True)
            )
    except Exception as exc:
        logger.warning(f"Chunk dir cleanup failed ({chunk_dir}): {exc}")


async def _forget(upload_id: str) -> None:
    """Закрывает сессию и убирает её чанки."""
    await asyncio.to_thread(_resume.upload_close, upload_id)
    await _discard_chunks(upload_id)


GONE = "Upload session not found or expired"
GONE_START_OVER = "Upload session not found or expired. Start over."


async def _live_session(upload_id: str, gone: str) -> dict:
    """Возвращает живую сессию или бросает 404, попутно убирая чанки протухшей."""
    try:
        told = await asyncio.to_thread(_resume.upload_find, upload_id)
    except ValueError:
        raise HTTPException(404, gone) from None
    if told["state"] == "expired":
        await _discard_chunks(upload_id)
    if told["state"] != "live":
        raise HTTPException(404, gone)
    return told


async def _owned_session(upload_id: str, user_id: int, gone: str = GONE) -> dict:
    told = await _live_session(upload_id, gone)
    if told["user_id"] != user_id:
        raise HTTPException(403, "No access to upload session")
    return told


# Вспомогательные функции


def _validate_hex_hash(value: str, field_name: str = "hash") -> str:
    """Проверяет, что строка является корректным SHA-256 hex (64 символа)."""
    value = value.strip().lower()
    if len(value) != 64:
        raise HTTPException(400, f"{field_name}: expected 64 hex chars, got {len(value)}")
    try:
        bytes.fromhex(value)
    except ValueError:
        raise HTTPException(400, f"{field_name}: invalid hex") from None
    return value


def _check_room_access(room_id: int, user_id: int, db: Session) -> None:
    """Бросает 403 если пользователь не является участником комнаты."""
    if room_id >= 0:
        member = (
            db.query(RoomMember)
            .filter(
                RoomMember.room_id == room_id,
                RoomMember.user_id == user_id,
                RoomMember.is_banned.is_(False),
            )
            .first()
        )
        if not member:
            raise HTTPException(403, "No access to room")


# 1. Инициализация сессии


@router.post("/api/files/upload-init")
async def upload_init(
    room_id: int = Form(...),
    file_name: str = Form(...),
    file_size: int = Form(...),
    file_hash: str = Form(...),
    chunk_size: int = Form(DEFAULT_CHUNK_SIZE),
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Инициализация сессии возобновляемой загрузки.

    Клиент передаёт:
      - room_id    — ID комнаты
      - file_name  — оригинальное имя файла
      - file_size  — полный размер в байтах
      - file_hash  — SHA-256 полного файла (64 hex-символа)
      - chunk_size — размер одного чанка (64КБ–10МБ, по умолчанию 1МБ)

    Ответ:
      - upload_id    — токен сессии для последующих запросов
      - total_chunks — ожидаемое количество чанков
      - chunk_size   — итоговый (скорректированный) размер чанка
      - received     — список уже принятых чанков (пусто для новой сессии)
    """
    _check_room_access(room_id, u.id, db)

    # Валидация размера файла — с учётом тарифа пользователя.
    # Free = 200 MB, Premium = 2 GB. MAX_FILE_SIZE остаётся абсолютным
    # потолком (3 GB по умолчанию), выше которого никто не загрузит
    # даже с премиумом — защита от ошибок конфига.
    from app.security.limits import get_limits_for_user

    tier = await get_limits_for_user(u)
    tier_limit_bytes = tier.max_file_mb * 1024 * 1024
    effective_limit = min(tier_limit_bytes, FileUploadConfig.MAX_FILE_SIZE)
    if file_size <= 0:
        raise HTTPException(400, {"error": "invalid_file_size", "size": file_size})
    if file_size > effective_limit:
        raise HTTPException(
            413,
            {
                "error": "file_too_large",
                "size": file_size,
                "limit_mb": effective_limit // 1024 // 1024,
                "tier": "premium" if tier.is_premium else "free",
                "upgrade_hint": (
                    None
                    if tier.is_premium
                    else "Link a Solana wallet with an active Vortex Premium subscription to upload files up to 2 GB."
                ),
            },
        )

    # Валидация имени файла
    if FileAnomalyDetector.detect_null_bytes(file_name):
        raise HTTPException(400, "Invalid characters in filename")
    if FileAnomalyDetector.detect_path_traversal(file_name):
        raise HTTPException(400, "Invalid filename")
    # mirror the direct path — reject double-extension web-shells
    # (shell.php.jpg) and web-shell/server-executable final extensions.
    if FileAnomalyDetector.detect_double_extension(file_name):
        raise HTTPException(400, "Invalid file extension")
    if Path(file_name).suffix.lower() in WEBSHELL_EXTS:
        raise HTTPException(400, "Invalid file extension")

    # Валидация хеша
    file_hash = _validate_hex_hash(file_hash, "file_hash")

    try:
        chunk_size, total_chunks = _resume.upload_plan(file_size, chunk_size)
    except ValueError as error:
        raise HTTPException(400, str(error)) from None

    upload_id = secrets.token_urlsafe(24)
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    _chunk_dir(upload_id).mkdir(parents=True, exist_ok=True)

    try:
        await asyncio.to_thread(
            _resume.upload_open,
            upload_id,
            room_id,
            u.id,
            file_name,
            file_size,
            total_chunks,
            file_hash,
        )
    except ValueError as error:
        await _discard_chunks(upload_id)
        raise HTTPException(400, str(error)) from None

    logger.info(
        f"[UploadInit] user={u.username} room={room_id} "
        f"file={file_name!r} size={file_size} chunks={total_chunks} id={upload_id}"
    )

    return {
        "upload_id": upload_id,
        "total_chunks": total_chunks,
        "chunk_size": chunk_size,
        "received": [],
    }


# 2. Загрузка чанка


@router.put("/api/files/upload-chunk/{upload_id}")
async def upload_chunk(
    upload_id: str,
    chunk_index: int = Form(...),
    chunk_hash: str = Form(...),
    data: UploadFile = File(...),
    u: User = Depends(get_current_user),
):
    """
    Загрузка одного чанка.

    Клиент передаёт:
      - chunk_index — порядковый номер чанка (0-based)
      - chunk_hash  — SHA-256 данного чанка (для верификации)
      - data        — бинарные данные чанка

    Операция идемпотентна: если чанк с таким индексом уже принят,
    сервер возвращает OK без повторной записи.
    """
    told = await _owned_session(upload_id, u.id, GONE_START_OVER)
    total_chunks = told["total_chunks"]

    if not (0 <= chunk_index < total_chunks):
        raise HTTPException(400, f"Invalid chunk index: {chunk_index} (expected 0-{total_chunks - 1})")

    # Идемпотентность: чанк уже принят
    if chunk_index in told["received"]:
        return {
            "ok": True,
            "chunk_index": chunk_index,
            "already_received": True,
            "progress": told["progress"],
        }

    # Читаем данные
    raw = await data.read()
    if not raw:
        raise HTTPException(400, f"Empty chunk {chunk_index}")

    # Проверяем хеш чанка — Rust-реализация даёт ~2 мс на 10 МБ чанк
    # вместо 15 мс в stdlib; при 100 МБ/с пропускной способности это
    # освобождает 13% CPU на сервере.
    chunk_hash = _validate_hex_hash(chunk_hash, "chunk_hash")
    actual_hash = _sha256_hex(raw)
    if actual_hash != chunk_hash:
        raise HTTPException(
            400, f"Chunk {chunk_index} hash mismatch. Expected: {chunk_hash[:16]}..., got: {actual_hash[:16]}..."
        )

    # Атомарная запись: сначала во временный файл, потом rename
    chunk_path = _chunk_dir(upload_id) / f"{chunk_index:06d}.chunk"
    tmp_path = chunk_path.with_suffix(".tmp")
    tmp_path.write_bytes(raw)
    tmp_path.rename(chunk_path)

    taken = await asyncio.to_thread(_resume.upload_receive, upload_id, chunk_index)
    if taken["outcome"] in ("missing", "expired"):
        await _discard_chunks(upload_id)
        raise HTTPException(404, GONE_START_OVER)

    logger.debug(
        f"[Chunk] {chunk_index}/{total_chunks - 1} upload={upload_id} progress={taken['progress']}%"
    )

    return {
        "ok": True,
        "chunk_index": chunk_index,
        "progress": taken["progress"],
        "missing": len(taken["missing"]),
        "complete": taken["complete"],
    }


# 3. Статус сессии


@router.get("/api/files/upload-status/{upload_id}")
async def upload_status(
    upload_id: str,
    u: User = Depends(get_current_user),
):
    """
    Возвращает список принятых чанков и прогресс.

    Клиент использует этот эндпоинт при возобновлении загрузки после
    разрыва соединения или перезагрузки страницы.
    """
    told = await _owned_session(upload_id, u.id)

    return {
        "upload_id": upload_id,
        "file_name": told["file_name"],
        "file_size": told["file_size"],
        "total_chunks": told["total_chunks"],
        "received": told["received"],
        "missing": told["missing"],
        "progress": told["progress"],
        "complete": told["complete"],
    }


# 4. Финализация (сборка файла)


@router.post("/api/files/upload-complete/{upload_id}")
async def upload_complete(
    upload_id: str,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Финализация загрузки: сборка чанков → проверка SHA-256 → сохранение.

    Последовательность:
      1. Проверить что все чанки получены.
      2. Собрать файл в памяти (stream по чанкам).
      3. Проверить SHA-256 против file_hash из init.
      4. Прогнать MIME-валидацию и проверки аномалий.
      5. Записать в Config.UPLOAD_DIR, создать FileTransfer + Message в БД.
      6. Broadcast в WebSocket комнаты.
      7. Удалить сессию и временные файлы.
    """
    told = await _owned_session(upload_id, u.id)

    missing = told["missing"]
    if missing:
        raise HTTPException(
            400,
            {
                "error": "Upload incomplete — there are missing chunks",
                "missing": missing[:20],
                "count": len(missing),
            },
        )

    assembled = bytearray()
    for idx in range(told["total_chunks"]):
        chunk_path = _chunk_dir(upload_id) / f"{idx:06d}.chunk"
        if not chunk_path.exists():
            # Это не должно произойти, но защищаемся
            raise HTTPException(500, f"Chunk {idx} missing on disk — retry upload")
        assembled.extend(chunk_path.read_bytes())

    content = bytes(assembled)
    del assembled

    actual_hash = _sha256_hex(content)
    if actual_hash != told["file_hash"]:
        await _forget(upload_id)
        raise HTTPException(
            400, f"File hash mismatch. Expected: {told['file_hash'][:16]}..., got: {actual_hash[:16]}..."
        )

    if FileAnomalyDetector.detect_zip_bomb_indicators(content):
        await _forget(upload_id)
        raise HTTPException(400, "File appears to be an archive bomb")

    mime_ok, mime_result = validate_file_mime_type(content, told["file_name"])
    if not mime_ok:
        await _forget(upload_id)
        raise HTTPException(415, mime_result or "Unsupported file type")
    mime_type = mime_result

    is_image = mime_type and mime_type.startswith("image/")
    _is_encrypted = len(content) > 12 and content[:4] not in (
        b"\xff\xd8\xff",
        b"\x89PNG",
        b"GIF8",
        b"RIFF",
    )
    if is_image and not _is_encrypted:
        img_ok, img_err = await FileAnomalyDetector.validate_image_content(content)
        if not img_ok:
            await _forget(upload_id)
            raise HTTPException(400, img_err or "Invalid image content")

    # strip ALL metadata before writing to disk, mirroring the direct
    # path (app/chats/messages/files.py:91). The chunked path previously stored
    # the assembled bytes verbatim, leaking EXIF/GPS (images), creation time and
    # device info (video/audio), and author/dates (PDF). The integrity check
    # above already validated the *uploaded* bytes against the session digest;
    # the stored hash/size are recomputed from the stripped content below.
    content = strip_all_metadata(content, mime_type)
    stored_hash = _sha256_hex(content)

    ext = Path(told["file_name"]).suffix.lower()
    safe_name = generate_secure_filename(ext)
    Config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    stored_path = Config.UPLOAD_DIR / safe_name
    stored_path.write_bytes(content)

    ft = FileTransfer(
        room_id=told["room_id"],
        uploader_id=u.id,
        original_name=told["file_name"],
        stored_name=safe_name,
        mime_type=mime_type,
        size_bytes=len(content),
        file_hash=stored_hash,
    )
    db.add(ft)
    db.commit()
    db.refresh(ft)

    download_url = f"/api/files/download/{ft.id}"

    is_voice = told["file_name"].startswith("voice_") and mime_type and mime_type.startswith("audio/")
    msg_type = MessageType.VOICE if is_voice else MessageType.IMAGE if is_image else MessageType.FILE

    placeholder_encrypted = b"\x00" * 12 + b"\x00" * 16
    msg = Message(
        room_id=told["room_id"],
        sender_id=u.id,
        msg_type=msg_type,
        content_encrypted=placeholder_encrypted,
        file_name=told["file_name"],
        file_size=len(content),
    )
    db.add(msg)
    db.commit()

    broadcast_payload = {
        "type": "file",
        "sender_id": u.id,
        "sender": u.username,
        "display_name": u.display_name or u.username,
        "avatar_emoji": u.avatar_emoji,
        "file_name": told["file_name"],
        "file_size": len(content),
        "mime_type": mime_type,
        "download_url": download_url,
        "msg_type": msg_type.value,
        "created_at": ft.created_at.isoformat(),
        "file_hash": stored_hash,  # hash of stored (stripped) bytes
    }
    await manager.broadcast_to_room(told["room_id"], broadcast_payload)

    logger.info(
        f"[UploadComplete] user={u.username} file={told['file_name']!r} "
        f"size={len(content)} room={told['room_id']} upload_id={upload_id}"
    )

    await _forget(upload_id)

    return {
        "ok": True,
        "file_id": ft.id,
        "download_url": download_url,
        "file_hash": stored_hash,  # hash of stored (stripped) bytes
        "size_bytes": len(content),
        "mime_type": mime_type,
    }


# 5. Отмена сессии


@router.delete("/api/files/upload-cancel/{upload_id}")
async def upload_cancel(
    upload_id: str,
    u: User = Depends(get_current_user),
):
    """
    Отменяет сессию загрузки и удаляет временные файлы чанков.
    Безопасно вызывать даже если сессия уже завершена или истекла.
    """
    try:
        told = await asyncio.to_thread(_resume.upload_find, upload_id)
    except ValueError:
        return {"ok": True, "message": "Session not found (already completed or expired)"}
    if told["state"] != "live":
        await _discard_chunks(upload_id)
        return {"ok": True, "message": "Session not found (already completed or expired)"}
    if told["user_id"] != u.id:
        raise HTTPException(403, "No access to upload session")

    await _forget(upload_id)
    logger.info(f"[UploadCancel] user={u.username} upload_id={upload_id}")
    return {"ok": True}


# Фоновая задача очистки протухших сессий


async def cleanup_sessions_loop(interval_sec: int = 3600) -> None:
    """
    Периодически удаляет протухшие сессии загрузки.

    Запускать как asyncio background task в lifespan приложения:

        asyncio.create_task(cleanup_sessions_loop())
    """
    while True:
        await asyncio.sleep(interval_sec)
        try:
            swept = await asyncio.to_thread(_resume.upload_sweep)
            for upload_id in swept:
                await _discard_chunks(upload_id)
            if swept:
                logger.info(f"[ResumableCleanup] Removed {len(swept)} expired sessions")
        except Exception as exc:
            logger.error(f"[ResumableCleanup] Cleanup error: {exc}")

"""
Saved GIFs API — пользователь сохраняет GIF на сервер для быстрого доступа.

Клиент расшифровывает GIF из комнаты, загружает на сервер.
При открытии GIF-панели — скачивает свои сохранённые GIF.
Файлы хранятся в uploads/saved_gifs/{user_id}/.
"""
from __future__ import annotations

import os
import uuid
import logging

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models_rooms.stickers import SavedGif
from app.keys.keys import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/gifs", tags=["saved_gifs"])

_MAX_GIF_SIZE = 10 * 1024 * 1024  # 10 MB


@router.get("/saved")
async def list_saved_gifs(
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Список сохранённых GIF пользователя."""
    gifs = (
        db.query(SavedGif)
        .filter(SavedGif.user_id == u.id)
        .order_by(SavedGif.created_at.desc())
        .limit(50)
        .all()
    )
    return [{"id": g.id, "url": g.file_url} for g in gifs]


@router.post("/saved")
async def save_gif(
    file: UploadFile = File(...),
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Сохранить GIF (клиент загружает уже расшифрованный файл)."""
    data = await file.read()
    if len(data) > _MAX_GIF_SIZE:
        raise HTTPException(400, "GIF too large (max 10 MB)")
    if len(data) < 6:
        raise HTTPException(400, "Invalid file")

    gif_dir = f"uploads/saved_gifs/{u.id}"
    os.makedirs(gif_dir, exist_ok=True)

    filename = f"{uuid.uuid4().hex}.gif"
    filepath = os.path.join(gif_dir, filename)
    with open(filepath, "wb") as f:
        f.write(data)

    file_url = f"/uploads/saved_gifs/{u.id}/{filename}"

    gif = SavedGif(user_id=u.id, file_url=file_url)
    db.add(gif)
    db.commit()
    db.refresh(gif)

    logger.info(f"GIF saved by {u.username} (id={gif.id})")
    return {"id": gif.id, "url": file_url}


@router.delete("/saved/{gif_id}")
async def delete_saved_gif(
    gif_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Удалить сохранённый GIF."""
    gif = db.query(SavedGif).filter(SavedGif.id == gif_id, SavedGif.user_id == u.id).first()
    if not gif:
        raise HTTPException(404, "GIF not found")

    # Remove file
    path = gif.file_url.lstrip("/")
    if os.path.isfile(path):
        os.remove(path)

    db.delete(gif)
    db.commit()
    return {"ok": True}

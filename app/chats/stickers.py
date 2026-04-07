"""
app/chats/stickers.py — Система стикер-паков.

Пользователи могут создавать паки стикеров, загружать изображения и делиться ими.
Поддерживаемые форматы: PNG, WEBP, GIF. Максимум 512 КБ. Ресайз до 256x256.

Endpoints:
  POST   /api/stickers/packs                              — создать пак
  GET    /api/stickers/packs                              — свои + избранные паки
  GET    /api/stickers/packs/public                       — все публичные паки
  GET    /api/stickers/packs/{pack_id}                    — пак с содержимым
  PUT    /api/stickers/packs/{pack_id}                    — обновить инфо (владелец)
  DELETE /api/stickers/packs/{pack_id}                    — удалить пак (владелец)
  POST   /api/stickers/packs/{pack_id}/stickers           — загрузить стикер
  DELETE /api/stickers/packs/{pack_id}/stickers/{sticker_id} — удалить стикер
  POST   /api/stickers/packs/{pack_id}/favorite           — добавить в избранное
  DELETE /api/stickers/packs/{pack_id}/favorite           — убрать из избранного

Формат стикера в сообщениях:
  [STICKER] img:/uploads/stickers/{pack_id}/{filename}
"""
from __future__ import annotations

import io
import logging
import os
import secrets as _secrets
import shutil

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import Sticker, StickerPack, UserFavoritePack
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/stickers", tags=["stickers"])

_MAX_STICKER_BYTES = 512 * 1024  # 512 KB
_MAX_SIDE = 256
_ALLOWED_FORMATS = {"PNG", "WEBP", "GIF"}


# ══════════════════════════════════════════════════════════════════════════════
# Schemas
# ══════════════════════════════════════════════════════════════════════════════

class PackCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    description: str = Field("", max_length=200)
    is_public: bool = True


class PackUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=50)
    description: str | None = Field(None, max_length=200)
    is_public: bool | None = None


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _sticker_dict(s: Sticker) -> dict:
    return {
        "id":         s.id,
        "pack_id":    s.pack_id,
        "emoji":      s.emoji,
        "image_url":  s.image_url,
        "order_idx":  s.order_idx,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


def _pack_dict(p: StickerPack, *, include_stickers: bool = False) -> dict:
    d = {
        "id":          p.id,
        "name":        p.name,
        "description": p.description,
        "creator_id":  p.creator_id,
        "cover_url":   p.cover_url,
        "is_public":   p.is_public,
        "created_at":  p.created_at.isoformat() if p.created_at else None,
        "sticker_count": len(p.stickers) if p.stickers else 0,
    }
    if include_stickers:
        stickers = sorted(p.stickers, key=lambda s: s.order_idx)
        d["stickers"] = [_sticker_dict(s) for s in stickers]
    return d


def _require_pack_owner(pack_id: int, user_id: int, db: Session) -> StickerPack:
    """Return the pack or raise 404/403."""
    pack = db.query(StickerPack).filter(StickerPack.id == pack_id).first()
    if not pack:
        raise HTTPException(404, "Стикер-пак не найден")
    if pack.creator_id != user_id:
        raise HTTPException(403, "Только создатель может управлять паком")
    return pack


# ══════════════════════════════════════════════════════════════════════════════
# Pack management
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/packs")
async def create_pack(
    body: PackCreate,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Создать новый стикер-пак."""
    pack = StickerPack(
        name=body.name,
        description=body.description,
        creator_id=u.id,
        is_public=body.is_public,
    )
    db.add(pack)
    db.commit()
    db.refresh(pack)
    logger.info(f"Sticker pack '{pack.name}' created by {u.username} (id={pack.id})")
    return {"ok": True, "pack": _pack_dict(pack)}


@router.get("/packs")
async def list_my_packs(
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Список собственных паков + избранных."""
    own = (
        db.query(StickerPack)
        .filter(StickerPack.creator_id == u.id)
        .order_by(StickerPack.created_at.desc())
        .all()
    )
    fav_pack_ids = (
        db.query(UserFavoritePack.pack_id)
        .filter(UserFavoritePack.user_id == u.id)
        .all()
    )
    fav_ids = [r[0] for r in fav_pack_ids]
    favorited = []
    if fav_ids:
        favorited = (
            db.query(StickerPack)
            .filter(StickerPack.id.in_(fav_ids))
            .all()
        )
    return {
        "own":       [_pack_dict(p, include_stickers=True) for p in own],
        "favorited": [_pack_dict(p, include_stickers=True) for p in favorited],
    }


@router.get("/packs/public")
async def list_public_packs(
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Все публичные паки (для каталога / поиска)."""
    packs = (
        db.query(StickerPack)
        .filter(StickerPack.is_public == True)
        .order_by(StickerPack.created_at.desc())
        .all()
    )
    fav_ids = set(
        r[0] for r in
        db.query(UserFavoritePack.pack_id)
        .filter(UserFavoritePack.user_id == u.id)
        .all()
    )
    result = []
    for p in packs:
        d = _pack_dict(p)
        d["is_favorited"] = p.id in fav_ids
        result.append(d)
    return {"packs": result}


@router.get("/packs/{pack_id}")
async def get_pack(
    pack_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Детали пака с полным списком стикеров."""
    pack = db.query(StickerPack).filter(StickerPack.id == pack_id).first()
    if not pack:
        raise HTTPException(404, "Стикер-пак не найден")
    if not pack.is_public and pack.creator_id != u.id:
        fav = db.query(UserFavoritePack).filter(
            UserFavoritePack.user_id == u.id,
            UserFavoritePack.pack_id == pack_id,
        ).first()
        if not fav:
            raise HTTPException(403, "Пак приватный")
    d = _pack_dict(pack, include_stickers=True)
    d["is_favorited"] = db.query(UserFavoritePack).filter(
        UserFavoritePack.user_id == u.id,
        UserFavoritePack.pack_id == pack_id,
    ).first() is not None
    return {"pack": d}


@router.put("/packs/{pack_id}")
async def update_pack(
    pack_id: int,
    body: PackUpdate,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Обновить информацию пака (только владелец)."""
    pack = _require_pack_owner(pack_id, u.id, db)
    if body.name is not None:
        pack.name = body.name
    if body.description is not None:
        pack.description = body.description
    if body.is_public is not None:
        pack.is_public = body.is_public
    db.commit()
    db.refresh(pack)
    return {"ok": True, "pack": _pack_dict(pack)}


@router.delete("/packs/{pack_id}")
async def delete_pack(
    pack_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Удалить пак и все стикеры (только владелец)."""
    pack = _require_pack_owner(pack_id, u.id, db)

    # Удаляем файлы стикеров с диска
    pack_dir = f"uploads/stickers/{pack_id}"
    if os.path.isdir(pack_dir):
        shutil.rmtree(pack_dir, ignore_errors=True)

    # Удаляем записи избранного у всех пользователей
    db.query(UserFavoritePack).filter(UserFavoritePack.pack_id == pack_id).delete()

    db.delete(pack)
    db.commit()
    logger.info(f"Sticker pack {pack_id} deleted by {u.username}")
    return {"ok": True, "deleted_pack_id": pack_id}


# ══════════════════════════════════════════════════════════════════════════════
# Sticker upload / delete
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/packs/{pack_id}/stickers")
async def upload_sticker(
    pack_id: int,
    file:  UploadFile = File(...),
    emoji: str = "\U0001f600",
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Загрузить стикер в пак.
    Форматы: PNG, WEBP, GIF. Макс. 512 КБ. Ресайз до 256x256.
    """
    pack = _require_pack_owner(pack_id, u.id, db)

    content = await file.read()
    if len(content) > _MAX_STICKER_BYTES:
        raise HTTPException(413, "Макс. 512 КБ")

    from PIL import Image

    try:
        img = Image.open(io.BytesIO(content))
    except Exception:
        raise HTTPException(400, "Неверный формат изображения")

    fmt = img.format
    if fmt not in _ALLOWED_FORMATS:
        raise HTTPException(
            400,
            f"Допустимые форматы: {', '.join(_ALLOWED_FORMATS)}. Получен: {fmt}",
        )

    # Ресайз с сохранением прозрачности
    is_animated = getattr(img, "is_animated", False)

    if not is_animated:
        # Для статичных изображений — thumbnail с сохранением alpha
        if img.mode not in ("RGBA", "LA", "P"):
            img = img.convert("RGBA")
        img.thumbnail((_MAX_SIDE, _MAX_SIDE), Image.LANCZOS)

    # Определяем формат сохранения
    if fmt == "GIF":
        save_ext = "gif"
        save_fmt = "GIF"
        save_kwargs = {}
        if is_animated:
            save_kwargs["save_all"] = True
    elif fmt == "WEBP":
        save_ext = "webp"
        save_fmt = "WEBP"
        save_kwargs = {"quality": 90}
    else:
        save_ext = "png"
        save_fmt = "PNG"
        save_kwargs = {}

    pack_dir = f"uploads/stickers/{pack_id}"
    os.makedirs(pack_dir, exist_ok=True)

    filename = f"{_secrets.token_hex(16)}.{save_ext}"
    filepath = os.path.join(pack_dir, filename)

    buf = io.BytesIO()
    img.save(buf, save_fmt, **save_kwargs)
    buf.seek(0)
    with open(filepath, "wb") as f:
        f.write(buf.read())

    image_url = f"/uploads/stickers/{pack_id}/{filename}"

    # Определяем order_idx как max+1
    max_order = db.query(Sticker.order_idx).filter(
        Sticker.pack_id == pack_id,
    ).order_by(Sticker.order_idx.desc()).first()
    next_order = (max_order[0] + 1) if max_order and max_order[0] is not None else 0

    sticker = Sticker(
        pack_id=pack_id,
        emoji=emoji[:10],
        image_url=image_url,
        order_idx=next_order,
    )
    db.add(sticker)

    # Обновляем обложку пака (первый стикер)
    if not pack.cover_url:
        pack.cover_url = image_url

    db.commit()
    db.refresh(sticker)

    logger.info(f"Sticker uploaded to pack {pack_id}: {filename}")
    return {"ok": True, "sticker": _sticker_dict(sticker)}


@router.delete("/packs/{pack_id}/stickers/{sticker_id}")
async def delete_sticker(
    pack_id: int,
    sticker_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Удалить стикер из пака (только владелец пака)."""
    _require_pack_owner(pack_id, u.id, db)

    sticker = db.query(Sticker).filter(
        Sticker.id == sticker_id,
        Sticker.pack_id == pack_id,
    ).first()
    if not sticker:
        raise HTTPException(404, "Стикер не найден")

    # Удаляем файл с диска
    if sticker.image_url:
        file_path = sticker.image_url.lstrip("/")
        if os.path.isfile(file_path):
            os.remove(file_path)

    db.delete(sticker)
    db.commit()

    logger.info(f"Sticker {sticker_id} deleted from pack {pack_id}")
    return {"ok": True, "deleted_sticker_id": sticker_id}


# ══════════════════════════════════════════════════════════════════════════════
# Favorites
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/packs/{pack_id}/favorite")
async def add_favorite(
    pack_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Добавить пак в избранное."""
    pack = db.query(StickerPack).filter(StickerPack.id == pack_id).first()
    if not pack:
        raise HTTPException(404, "Стикер-пак не найден")

    existing = db.query(UserFavoritePack).filter(
        UserFavoritePack.user_id == u.id,
        UserFavoritePack.pack_id == pack_id,
    ).first()
    if existing:
        return {"ok": True, "already_favorited": True}

    fav = UserFavoritePack(user_id=u.id, pack_id=pack_id)
    db.add(fav)
    db.commit()
    return {"ok": True, "favorited": True, "pack_id": pack_id}


@router.delete("/packs/{pack_id}/favorite")
async def remove_favorite(
    pack_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Убрать пак из избранного."""
    fav = db.query(UserFavoritePack).filter(
        UserFavoritePack.user_id == u.id,
        UserFavoritePack.pack_id == pack_id,
    ).first()
    if not fav:
        raise HTTPException(404, "Пак не в избранном")
    db.delete(fav)
    db.commit()
    return {"ok": True, "removed": True, "pack_id": pack_id}

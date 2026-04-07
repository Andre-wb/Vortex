"""
Translation endpoint — proxies requests to a LibreTranslate instance.
Rate-limited to 50 translations per user per hour (in-memory).
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.config import Config
from app.models import User
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/translate", tags=["translate"])

# ── Rate limiting (in-memory) ────────────────────────────────────────────────
_RATE_LIMIT = 50
_RATE_WINDOW = 3600  # 1 hour

_user_hits: dict[int, list[float]] = defaultdict(list)


def _check_rate_limit(user_id: int) -> None:
    now = time.time()
    cutoff = now - _RATE_WINDOW
    hits = _user_hits[user_id]
    # Cleanup old entries
    _user_hits[user_id] = [t for t in hits if t > cutoff]
    if len(_user_hits[user_id]) >= _RATE_LIMIT:
        raise HTTPException(429, "Translation rate limit exceeded (50/hour)")
    _user_hits[user_id].append(now)


# ── Schemas ──────────────────────────────────────────────────────────────────

class TranslateRequest(BaseModel):
    text: str
    source: str = "auto"
    target: str = "ru"


class TranslateResponse(BaseModel):
    translatedText: str
    detectedLanguage: Optional[str] = None


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("", response_model=TranslateResponse)
async def translate_text(
    body: TranslateRequest,
    u: User = Depends(get_current_user),
):
    """Translate text via LibreTranslate."""
    if not Config.TRANSLATE_ENABLED:
        raise HTTPException(503, "Translation service is disabled")

    _check_rate_limit(u.id)

    url = f"{Config.TRANSLATE_URL.rstrip('/')}/translate"
    payload = {
        "q": body.text,
        "source": body.source,
        "target": body.target,
        "format": "text",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as exc:
        logger.warning("LibreTranslate HTTP error: %s", exc)
        raise HTTPException(502, "Translation service returned an error")
    except Exception as exc:
        logger.warning("LibreTranslate connection error: %s", exc)
        raise HTTPException(502, "Translation service unavailable")

    detected = None
    if isinstance(data.get("detectedLanguage"), dict):
        detected = data["detectedLanguage"].get("language")
    elif isinstance(data.get("detectedLanguage"), str):
        detected = data["detectedLanguage"]

    return TranslateResponse(
        translatedText=data.get("translatedText", ""),
        detectedLanguage=detected,
    )


@router.get("/languages")
async def translate_languages(
    u: User = Depends(get_current_user),
):
    """Proxy LibreTranslate /languages to get available language list."""
    if not Config.TRANSLATE_ENABLED:
        raise HTTPException(503, "Translation service is disabled")

    url = f"{Config.TRANSLATE_URL.rstrip('/')}/languages"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        logger.warning("LibreTranslate /languages error: %s", exc)
        raise HTTPException(502, "Translation service unavailable")

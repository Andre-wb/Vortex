"""
Translation endpoint — proxies requests to a LibreTranslate instance.
Rate-limited to 50 translations per user per hour (общий счёт на весь кластер).
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.config import Config
from app.models import User
from app.security import ratelimit_backend as _ratelimit
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/translate", tags=["translate"])

def _check_rate_limit(user_id: int) -> None:
    if not _ratelimit.translation_allowed(user_id):
        raise HTTPException(429, "Translation rate limit exceeded (50/hour)")


class TranslateRequest(BaseModel):
    text: str
    source: str = "auto"
    target: str = "ru"


class TranslateResponse(BaseModel):
    translatedText: str  # noqa: N815
    detectedLanguage: Optional[str] = None  # noqa: N815


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
        raise HTTPException(502, "Translation service returned an error") from None
    except Exception as exc:
        logger.warning("LibreTranslate connection error: %s", exc)
        raise HTTPException(502, "Translation service unavailable") from None

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
        raise HTTPException(502, "Translation service unavailable") from None

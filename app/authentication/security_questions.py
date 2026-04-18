"""Security Questions — восстановление пароля через секретные вопросы.

Ответы хешируются через PBKDF2-SHA256 (600K итераций) и хранятся в БД.
При восстановлении ответы верифицируются, и выдаётся JWT.
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import Session

from app.base import Base
from app.database import get_db
from app.models import User
from app.security.auth_jwt import get_current_user, create_access_token

from app.authentication._helpers import router

logger = logging.getLogger(__name__)

_PBKDF2_ITERATIONS = 600_000


# ── Model ────────────────────────────────────────────────────────────────────

class SecurityQuestion(Base):
    __tablename__ = "security_questions"

    id        = Column(Integer, primary_key=True, autoincrement=True)
    user_id   = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    question  = Column(String(200), nullable=False)
    answer_hash = Column(String(256), nullable=False)  # salt:hash
    order_idx = Column(Integer, default=0)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _hash_answer(answer: str, salt: str | None = None) -> str:
    """Hash an answer with PBKDF2-SHA256. Returns 'salt:hash'."""
    normalized = answer.strip().lower()
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", normalized.encode(), salt.encode(), _PBKDF2_ITERATIONS)
    return f"{salt}:{h.hex()}"


def _verify_answer(answer: str, stored: str) -> bool:
    """Verify an answer against stored 'salt:hash'."""
    parts = stored.split(":", 1)
    if len(parts) != 2:
        return False
    salt, expected_hash = parts
    normalized = answer.strip().lower()
    h = hashlib.pbkdf2_hmac("sha256", normalized.encode(), salt.encode(), _PBKDF2_ITERATIONS)
    return h.hex() == expected_hash


# ── Schemas ──────────────────────────────────────────────────────────────────

class SetupRequest(BaseModel):
    questions: list[str]  # 3 questions
    answers: list[str]    # 3 answers


class LoadRequest(BaseModel):
    username: str


class RecoverRequest(BaseModel):
    username: str
    answers: list[str]  # 3 answers


# ── Default questions for onboarding ─────────────────────────────────────────

DEFAULT_QUESTIONS = [
    "Имя вашего первого питомца?",
    "В каком городе вы родились?",
    "Любимый фильм в детстве?",
]

DEFAULT_QUESTIONS_EN = [
    "Name of your first pet?",
    "City where you were born?",
    "Favorite childhood movie?",
]


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/security-questions/setup")
async def setup_security_questions(
    body: SetupRequest,
    u: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Setup 3 security questions + answers for password recovery."""
    if len(body.questions) != 3 or len(body.answers) != 3:
        raise HTTPException(400, "Exactly 3 questions and 3 answers required")

    for q, a in zip(body.questions, body.answers):
        if not q.strip() or not a.strip():
            raise HTTPException(400, "Questions and answers cannot be empty")

    # Delete old questions
    db.query(SecurityQuestion).filter(SecurityQuestion.user_id == u.id).delete()

    # Save new
    for i, (q, a) in enumerate(zip(body.questions, body.answers)):
        db.add(SecurityQuestion(
            user_id=u.id,
            question=q.strip(),
            answer_hash=_hash_answer(a),
            order_idx=i,
        ))
    db.commit()
    logger.info("Security questions set for user %s", u.username)
    return {"ok": True}


@router.post("/security-questions/load")
async def load_security_questions(
    body: LoadRequest,
    db: Session = Depends(get_db),
):
    """Load questions (not answers!) for a username. Public endpoint."""
    user = db.query(User).filter(User.username == body.username).first()
    if not user:
        raise HTTPException(404, "User not found")

    questions = (
        db.query(SecurityQuestion)
        .filter(SecurityQuestion.user_id == user.id)
        .order_by(SecurityQuestion.order_idx)
        .all()
    )
    if not questions:
        return {"questions": []}

    return {"questions": [q.question for q in questions]}


@router.post("/security-questions/recover")
async def recover_with_security_questions(
    body: RecoverRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Verify 3 answers and issue JWT if correct."""
    from fastapi import Request as _Req
    user = db.query(User).filter(User.username == body.username).first()
    if not user:
        raise HTTPException(404, "User not found")

    if len(body.answers) != 3:
        raise HTTPException(400, "3 answers required")

    questions = (
        db.query(SecurityQuestion)
        .filter(SecurityQuestion.user_id == user.id)
        .order_by(SecurityQuestion.order_idx)
        .all()
    )

    if len(questions) != 3:
        raise HTTPException(400, "Security questions not configured")

    # Verify all 3
    for q, answer in zip(questions, body.answers):
        if not _verify_answer(answer, q.answer_hash):
            raise HTTPException(403, "Incorrect answers")

    # All correct — set auth cookies and mark as recovery
    from fastapi.responses import JSONResponse
    from app.authentication._helpers import _set_auth_cookies

    data = {
        "access_token": "set-via-cookie",
        "user_id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "recovery": True,
    }
    response = JSONResponse(content=data)
    _set_auth_cookies(response, user, db, request)

    # Mark the newest device as recovery session
    from app.models import UserDevice
    newest = db.query(UserDevice).filter(
        UserDevice.user_id == user.id
    ).order_by(UserDevice.id.desc()).first()
    if newest:
        newest.device_name = f"recovery:{newest.device_name or 'unknown'}"
        db.commit()

    logger.info("Password recovery via security questions: %s", user.username)
    return response


@router.get("/security-questions/defaults")
async def get_default_questions():
    """Return default question templates for onboarding."""
    return {
        "ru": DEFAULT_QUESTIONS,
        "en": DEFAULT_QUESTIONS_EN,
    }

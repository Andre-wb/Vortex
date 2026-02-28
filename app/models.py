"""Модели пользователей. Идентификатор = номер телефона."""
from __future__ import annotations
from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import relationship
from app.database import Base
from app.security.crypto import hash_password, verify_password


class User(Base):
    __tablename__ = "users"

    id               = Column(Integer, primary_key=True, index=True)
    phone            = Column(String(20),  unique=True, nullable=False, index=True)
    username         = Column(String(50),  unique=True, nullable=False, index=True)
    password_hash    = Column(String(512), nullable=False)
    display_name     = Column(String(100), nullable=True)
    avatar_emoji     = Column(String(10),  default="👤")

    # X25519 публичный ключ (32 байта, hex-encoded)
    x25519_public_key = Column(String(64),  nullable=True)

    is_active        = Column(Boolean, default=True)
    created_at       = Column(DateTime, default=datetime.utcnow)
    last_seen        = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    room_memberships = relationship(
        "RoomMember", back_populates="user", cascade="all, delete-orphan"
    )

    def set_password(self, password: str) -> None:
        self.password_hash = hash_password(password)

    def check_password(self, password: str) -> bool:
        return verify_password(password, self.password_hash)

    def __repr__(self) -> str:
        return f"<User id={self.id} phone={self.phone} username={self.username}>"


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id         = Column(Integer,    primary_key=True)
    user_id    = Column(Integer,    nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False)
    expires_at = Column(DateTime,   nullable=False)
    revoked_at = Column(DateTime,   nullable=True)
    created_at = Column(DateTime,   default=datetime.utcnow)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
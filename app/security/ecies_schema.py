"""Общая Pydantic-база обёртки ключа: классический ECIES или post-quantum гибрид.

Единая схема для всех путей раздачи ключей (DM, комнаты, каналы), чтобы гибрид
(X25519 + ML-KEM-768) принимался и хранился одинаково, без дивергенции.

  Классика: {ephemeral_pub, ciphertext}
  Гибрид:   {hybrid, x25519_ephemeral_pub, kyber_ciphertext, ciphertext}

X25519-эфемерный хранится в единой колонке ephemeral_pub независимо от формы;
наличие kyber_ciphertext ⟹ конверт гибридный.

Правила формата (длины, строгий hex, форма конверта) живут в `vortex-proto`;
модель описывает только типы полей для FastAPI и OpenAPI.
"""

from __future__ import annotations

import json

from pydantic import BaseModel

from app.security.wrapped_key_backend import wrapped_key_parse


class EciesKeyFields(BaseModel):
    ephemeral_pub: str | None = None
    ciphertext: str = ""
    hybrid: bool | None = None
    x25519_ephemeral_pub: str | None = None
    kyber_ciphertext: str | None = None

    def parsed(self):
        """Разбор конверта Rust-ом: объект WrappedKey либо None, если конверт негоден."""
        return wrapped_key_parse(
            json.dumps(
                {
                    "ephemeral_pub": self.ephemeral_pub,
                    "ciphertext": self.ciphertext,
                    "hybrid": self.hybrid,
                    "x25519_ephemeral_pub": self.x25519_ephemeral_pub,
                    "kyber_ciphertext": self.kyber_ciphertext,
                }
            )
        )

    @property
    def eph_pub(self) -> str | None:
        """X25519 эфемерный pub для хранения (единая колонка для обеих форм)."""
        parsed = self.parsed()
        return parsed.ephemeral_pub if parsed else None

    def ecies_dict(self) -> dict:
        """Форма для validate_ecies_payload и релея клиенту (по разобранному конверту)."""
        parsed = self.parsed()
        if parsed is None:
            return {
                "ephemeral_pub": self.ephemeral_pub,
                "ciphertext": self.ciphertext,
            }
        return parsed.client_dict()

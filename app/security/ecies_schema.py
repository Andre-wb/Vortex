"""Общая Pydantic-база обёртки ключа: классический ECIES или post-quantum гибрид.

Единая схема для всех путей раздачи ключей (DM, комнаты, каналы), чтобы гибрид
(X25519 + ML-KEM-768) принимался и хранился одинаково, без дивергенции.

  Классика: {ephemeral_pub, ciphertext}
  Гибрид:   {hybrid, x25519_ephemeral_pub, kyber_ciphertext, ciphertext}

X25519-эфемерный хранится в единой колонке ephemeral_pub независимо от формы;
наличие kyber_ciphertext ⟹ конверт гибридный.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator


class EciesKeyFields(BaseModel):
    ephemeral_pub: str | None = Field(default=None, min_length=64, max_length=64)
    ciphertext: str = Field(..., min_length=24)
    hybrid: bool | None = None
    x25519_ephemeral_pub: str | None = Field(default=None, min_length=64, max_length=64)
    kyber_ciphertext: str | None = Field(default=None, min_length=2176, max_length=2176)

    @model_validator(mode="after")
    def _check_ecies_shape(self):
        if self.hybrid:
            if not (self.x25519_ephemeral_pub and self.kyber_ciphertext):
                raise ValueError("hybrid payload requires x25519_ephemeral_pub and kyber_ciphertext")
        elif not self.ephemeral_pub:
            raise ValueError("classical payload requires ephemeral_pub")
        return self

    @property
    def eph_pub(self) -> str:
        """X25519 эфемерный pub для хранения (единая колонка для обеих форм)."""
        return self.x25519_ephemeral_pub if self.hybrid else self.ephemeral_pub

    def ecies_dict(self) -> dict:
        """Форма для validate_ecies_payload и релея клиенту (по наличию kyber_ciphertext)."""
        if self.hybrid:
            return {
                "hybrid": True,
                "x25519_ephemeral_pub": self.x25519_ephemeral_pub,
                "kyber_ciphertext": self.kyber_ciphertext,
                "ciphertext": self.ciphertext,
            }
        return {"ephemeral_pub": self.ephemeral_pub, "ciphertext": self.ciphertext}

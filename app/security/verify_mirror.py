"""app/security/verify_mirror.py — кросс-девайсный мирор OOB-верификаций (ADR-008 §4.2).

Сервер здесь — НЕподделываемое хранилище, не источник доверия. Он не имеет ни
device-, ни account-приватного ключа владельца → сфабриковать «я сверил пира» не
может. Каждая запись подписана device-ключом владельца, а device-cert связывает
этот ключ с account-Ed владельца. Верифицирует и применяет запись ДРУГОЕ устройство
владельца (device-cert→свой account-Ed + attest-sig). Сервер лишь хранит и отдаёт
владельцу его же записи (owner == current_user; чужие недоступны).

Заворачивание room-key (ADR-008 G3) всё равно НЕЗАВИСИМО ре-чекает живой ed против
сохранённого верифицированного — мирор синхронизирует лишь локальный hint, не
подменяет проверку. Компрометация сервера не даёт заворачивания на подменённый ключ.
"""

import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, VerificationAttestation
from app.security.auth_jwt import get_current_user

router = APIRouter(prefix="/api/verify", tags=["verify-mirror"])

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX128 = re.compile(r"^[0-9a-fA-F]{128}$")
_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")


class AttestationIn(BaseModel):
    peer_user_id: int
    verified_ed: str
    state: str  # verified | revoked
    signed_at: int
    client_device_id: str
    device_x3dh_pub: str
    device_sign_pub: str
    device_cert_sig: str
    attest_sig: str


@router.post("/attestations")
async def put_attestation(
    body: AttestationIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Сохранить подписанную атестацию верификации (latest-per-peer выигрывает).

    Гигиена формата (не проверка подписи — это работа устройства-потребителя):
    сервер отклоняет мусор по длинам/hex, но НЕ верифицирует крипто и не может.
    Монотонность по signed_at не даёт откатить свежую запись реплеем старой.
    """
    if body.state not in ("verified", "revoked"):
        raise HTTPException(400, "state must be verified|revoked")
    if (
        not _HEX64.match(body.verified_ed)
        or not _HEX64.match(body.device_x3dh_pub)
        or not _HEX64.match(body.device_sign_pub)
    ):
        raise HTTPException(400, "bad hex-64 field")
    if not _HEX128.match(body.device_cert_sig) or not _HEX128.match(body.attest_sig):
        raise HTTPException(400, "bad hex-128 signature")
    if not _HEX32.match(body.client_device_id):
        raise HTTPException(400, "bad client_device_id")

    existing = (
        db.query(VerificationAttestation)
        .filter(
            VerificationAttestation.owner_user_id == user.id,
            VerificationAttestation.peer_user_id == body.peer_user_id,
        )
        .first()
    )
    # Реплей старой записи не должен откатывать свежую (rollback-guard).
    if existing and existing.signed_at >= body.signed_at:
        return {"ok": True, "applied": False}

    if existing:
        existing.verified_ed = body.verified_ed.lower()
        existing.state = body.state
        existing.signed_at = body.signed_at
        existing.client_device_id = body.client_device_id.lower()
        existing.device_x3dh_pub = body.device_x3dh_pub.lower()
        existing.device_sign_pub = body.device_sign_pub.lower()
        existing.device_cert_sig = body.device_cert_sig.lower()
        existing.attest_sig = body.attest_sig.lower()
    else:
        db.add(
            VerificationAttestation(
                owner_user_id=user.id,
                peer_user_id=body.peer_user_id,
                verified_ed=body.verified_ed.lower(),
                state=body.state,
                signed_at=body.signed_at,
                client_device_id=body.client_device_id.lower(),
                device_x3dh_pub=body.device_x3dh_pub.lower(),
                device_sign_pub=body.device_sign_pub.lower(),
                device_cert_sig=body.device_cert_sig.lower(),
                attest_sig=body.attest_sig.lower(),
            )
        )
    db.commit()
    return {"ok": True, "applied": True}


@router.get("/attestations")
async def get_attestations(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Отдать владельцу ЕГО ЖЕ атестации (latest-per-peer). Чужие недоступны."""
    rows = db.query(VerificationAttestation).filter(VerificationAttestation.owner_user_id == user.id).all()
    return {
        "attestations": [
            {
                "peer_user_id": r.peer_user_id,
                "verified_ed": r.verified_ed,
                "state": r.state,
                "signed_at": r.signed_at,
                "client_device_id": r.client_device_id,
                "device_x3dh_pub": r.device_x3dh_pub,
                "device_sign_pub": r.device_sign_pub,
                "device_cert_sig": r.device_cert_sig,
                "attest_sig": r.attest_sig,
            }
            for r in rows
        ],
    }

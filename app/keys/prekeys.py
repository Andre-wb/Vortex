"""
app/keys/prekeys.py — API for publishing and retrieving Pre-Key Bundles (X3DH / Double Ratchet).

Endpoints:
  POST /api/keys/prekeys/publish   — upload SPK + batch of OPKs.
  GET  /api/keys/prekeys/{user_id} — retrieve Pre-Key Bundle (consumes one OPK).

Формат бандла, его проверка и форма ответов живут в Rust (`vortex-proto`,
загрузка — `prekeys_backend`); здесь только маршруты и работа с БД.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.config import Config
from app.database import get_db
from app.keys.prekeys_backend import (
    StoredPreKeyBundle,
    prekey_bundle_list,
    prekey_bundle_response,
    prekey_claim_response,
    prekey_client_device_id,
    prekey_needs_replenishment,
    prekey_parse_publish,
    prekey_status_published,
    prekey_status_unpublished,
)
from app.models import User, UserDevice
from app.models.prekeys import OneTimeKyberPreKey, OneTimePreKey, PreKeyBundle
from app.security.auth_jwt import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/keys/prekeys", tags=["prekeys"])


def _validated_client_device_id(request: Request) -> Optional[str]:
    """Return the caller's X-Device-Id header if Rust accepts it as a device id."""
    return prekey_client_device_id(request.headers.get("x-device-id"))


def _resolve_device_id(request: Request, user_id: int, db: Session) -> Optional[int]:
    """Map the caller's X-Device-Id header to a UserDevice.id for this user.

    Returns None when the header is absent/malformed or no matching device row
    exists — the bundle is then stored/looked-up under device_id=NULL (a client
    without a stable device id, or a test client sending no header).
    """
    cid = _validated_client_device_id(request)
    if cid is None:
        return None
    device = db.query(UserDevice).filter(UserDevice.user_id == user_id, UserDevice.client_device_id == cid).first()
    return device.id if device is not None else None


def _consume_one_opk(db: Session, user_id: int, device_id: Optional[int]) -> tuple[Optional[bytes], Optional[int]]:
    """Mark one unused OPK of (user_id, device_id) as used; return (public, key_id).

    Returns (None, None) when the device has no OPK left — X3DH may proceed
    without an OPK. Does not commit; caller commits.
    """
    opk: Optional[OneTimePreKey] = (
        db.query(OneTimePreKey)
        .filter(
            OneTimePreKey.user_id == user_id,
            OneTimePreKey.device_id == device_id,
            OneTimePreKey.used == False,  # noqa: E712
        )
        .order_by(OneTimePreKey.id)
        .first()
    )
    if opk is None:
        return None, None
    opk.used = True
    return opk.public_key, opk.key_id


def _consume_one_kyber_opk(
    db: Session, user_id: int, device_id: Optional[int]
) -> tuple[Optional[bytes], Optional[int]]:
    """Отмечает один неиспользованный PQOPK (user_id, device_id) как used (PQXDH P6).

    Зеркалит _consume_one_opk. (None, None) когда пул пуст — X3DH-PQ идёт на
    last-resort PQSPK. Не коммитит; коммитит вызывающий.
    """
    pqopk: Optional[OneTimeKyberPreKey] = (
        db.query(OneTimeKyberPreKey)
        .filter(
            OneTimeKyberPreKey.user_id == user_id,
            OneTimeKyberPreKey.device_id == device_id,
            OneTimeKyberPreKey.used == False,  # noqa: E712
        )
        .order_by(OneTimeKyberPreKey.id)
        .first()
    )
    if pqopk is None:
        return None, None
    pqopk.used = True
    return pqopk.public_key, pqopk.key_id


def _stored(bundle: PreKeyBundle) -> StoredPreKeyBundle:
    """Строка БД в том виде, в каком её принимает Rust-рендерер ответа."""
    return StoredPreKeyBundle(
        identity_key=bundle.identity_key,
        signed_prekey=bundle.signed_prekey,
        signed_prekey_sig=bundle.signed_prekey_sig,
        signed_prekey_id=bundle.signed_prekey_id,
        device_id=bundle.device_id,
        identity_key_ed=bundle.identity_key_ed,
        identity_key_sig=bundle.identity_key_sig,
        supports_v2=bundle.supports_v2,
        device_x3dh_pub=bundle.device_x3dh_pub,
        device_sign_pub=bundle.device_sign_pub,
        device_cert_sig=bundle.device_cert_sig,
        client_device_id=bundle.client_device_id,
        device_kyber_pub=bundle.device_kyber_pub,
        device_kyber_sig=bundle.device_kyber_sig,
        device_kyber_id=bundle.device_kyber_id,
    )


def _available_opk_count(db: Session, user_id: int, device_id: Optional[int]) -> int:
    return (
        db.query(OneTimePreKey)
        .filter(
            OneTimePreKey.user_id == user_id,
            OneTimePreKey.device_id == device_id,
            OneTimePreKey.used == False,  # noqa: E712
        )
        .count()
    )


class OneTimePreKeyUpload(BaseModel):
    """A single one-time Pre-Key for upload."""

    key_id: int = Field(..., description="Local OPK identifier (assigned by client)")
    public_key: str = Field(..., description="X25519 public key in hex (32 bytes = 64 hex chars)")


class OneTimeKyberPreKeyUpload(BaseModel):
    """A single one-time Kyber Pre-Key (ML-KEM-768) for upload (PQXDH P6)."""

    key_id: int = Field(..., description="Local PQOPK identifier (assigned by client)")
    public_key: str = Field(..., description="ML-KEM-768 public key in hex (1184 bytes = 2368 hex chars)")


class PublishPreKeysRequest(BaseModel):
    """Request to publish a Pre-Key Bundle.

    Client sends its Identity Key, Signed Pre-Key (with signature)
    and a batch of One-Time Pre-Keys. Правила формата не описаны здесь
    намеренно: длины, hex и пределы пачек проверяет Rust, иначе они двоились бы.
    """

    identity_key: str = Field(..., description="X25519 public Identity Key in hex")
    signed_prekey: str = Field(..., description="X25519 public Signed Pre-Key in hex")
    signed_prekey_sig: str = Field(..., description="Ed25519 signature of SPK in hex")
    signed_prekey_id: int = Field(..., description="SPK identifier for rotation")
    identity_key_ed: Optional[str] = Field(
        default=None,
        description="Ed25519 public identity key in hex (used to verify signatures). Optional for pre-batch-4 clients.",
    )
    identity_key_sig: Optional[str] = Field(
        default=None,
        description="Ed25519 signature of the X25519 identity_key, binding it to "
        "identity_key_ed. Optional for pre-batch-4 clients.",
    )
    supports_v2: Optional[bool] = Field(
        default=None,
        description="Client can RECEIVE v2 Double Ratchet messages.",
    )
    device_x3dh_pub: Optional[str] = Field(
        default=None,
        description="X25519 device X3DH public key in hex (device-identity triple).",
    )
    device_sign_pub: Optional[str] = Field(
        default=None,
        description="Ed25519 device signing public key in hex (device-identity triple).",
    )
    device_cert_sig: Optional[str] = Field(
        default=None,
        description="Ed25519 account signature over (client_device_id ‖ device_x3dh_pub ‖ "
        "device_sign_pub) in hex. Null when the account Ed25519 is not on this device.",
    )
    device_kyber_pub: Optional[str] = Field(
        default=None,
        description="ML-KEM-768 Kyber pre-key public in hex (1184 bytes = 2368 hex). PQXDH.",
    )
    device_kyber_sig: Optional[str] = Field(
        default=None,
        description="Ed25519 signature of device_kyber_pub by device_sign_pub in hex.",
    )
    device_kyber_id: Optional[int] = Field(
        default=None,
        description="Kyber pre-key id for rotation.",
    )
    one_time_prekeys: list[OneTimePreKeyUpload] = Field(
        default_factory=list,
        description="Bundle of one-time Pre-Keys",
    )
    one_time_kyber_prekeys: list[OneTimeKyberPreKeyUpload] = Field(
        default_factory=list,
        description="Bundle of one-time Kyber Pre-Keys (ML-KEM-768, PQXDH P6)",
    )


class PreKeyBundleResponse(BaseModel):
    """Response with a user's Pre-Key Bundle."""

    user_id: int
    device_id: Optional[int] = None
    identity_key: str
    signed_prekey: str
    signed_prekey_sig: str
    signed_prekey_id: int
    identity_key_ed: Optional[str] = None
    identity_key_sig: Optional[str] = None
    supports_v2: Optional[bool] = None
    device_x3dh_pub: Optional[str] = None
    device_sign_pub: Optional[str] = None
    device_cert_sig: Optional[str] = None
    client_device_id: Optional[str] = None
    device_kyber_pub: Optional[str] = None
    device_kyber_sig: Optional[str] = None
    device_kyber_id: Optional[int] = None
    one_time_prekey: Optional[str] = None
    one_time_prekey_id: Optional[int] = None


class DeviceBundle(BaseModel):
    """One device's Pre-Key Bundle within a multi-device fetch."""

    device_id: Optional[int] = None
    identity_key: str
    signed_prekey: str
    signed_prekey_sig: str
    signed_prekey_id: int
    identity_key_ed: Optional[str] = None
    identity_key_sig: Optional[str] = None
    supports_v2: Optional[bool] = None
    device_x3dh_pub: Optional[str] = None
    device_sign_pub: Optional[str] = None
    device_cert_sig: Optional[str] = None
    client_device_id: Optional[str] = None
    device_kyber_pub: Optional[str] = None
    device_kyber_sig: Optional[str] = None
    device_kyber_id: Optional[int] = None
    one_time_prekey: Optional[str] = None
    one_time_prekey_id: Optional[int] = None


class PreKeyBundleListResponse(BaseModel):
    """All active per-device Pre-Key Bundles for a user (Sesame fan-out discovery).

    One entry per publishing device; OPK НЕ включён (см. /claim-opk).
    """

    user_id: int
    bundles: list[DeviceBundle]


class ClaimOpkRequest(BaseModel):
    """Claim one OPK of a specific device for X3DH establishment."""

    device_id: Optional[int] = None
    want_kyber: bool = False


class ClaimOpkResponse(BaseModel):
    one_time_prekey: Optional[str] = None
    one_time_prekey_id: Optional[int] = None
    one_time_kyber_prekey: Optional[str] = None
    one_time_kyber_prekey_id: Optional[int] = None


class PreKeyStatusResponse(BaseModel):
    """Pre-Key Bundle status."""

    published: bool
    signed_prekey_id: Optional[int] = None
    available_opk_count: int = 0
    low_opk_warning: bool = False
    supports_v2: Optional[bool] = None


@router.post("/publish", response_model=PreKeyStatusResponse)
async def publish_prekeys(
    body: PublishPreKeysRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PreKeyStatusResponse:
    """Publishes or updates the current device's Pre-Key Bundle.

    The publishing device is resolved from the X-Device-Id header; its bundle is
    upserted on (user_id, device_id). If a record already exists — updates SPK
    (and signature). One-time keys are added to that device's pool.

    Решение «принять или отклонить» целиком за Rust: разбор идёт до любой записи
    в БД, поэтому отклонённый бандл никогда не сохраняется частично. Флаг
    PREKEY_SIG_ENFORCE читается на каждом вызове — тесты его переключают.
    """
    parsed = prekey_parse_publish(body.model_dump_json(), Config.PREKEY_SIG_ENFORCE)
    if parsed.rejection is not None:
        raise HTTPException(status_code=parsed.rejection.status, detail=parsed.rejection.detail)

    for detail in parsed.complaints:
        logger.warning("User %d prekey publish: %s (warn-only, accepted)", user.id, detail)

    device_id = _resolve_device_id(request, user.id, db)
    client_device_id = _validated_client_device_id(request)
    bundle: Optional[PreKeyBundle] = (
        db.query(PreKeyBundle).filter(PreKeyBundle.user_id == user.id, PreKeyBundle.device_id == device_id).first()
    )

    now = datetime.now(timezone.utc)

    if bundle is None:
        bundle = PreKeyBundle(
            user_id=user.id,
            device_id=device_id,
            identity_key=parsed.identity_key,
            signed_prekey=parsed.signed_prekey,
            signed_prekey_sig=parsed.signed_prekey_sig,
            signed_prekey_id=parsed.signed_prekey_id,
            identity_key_ed=parsed.identity_key_ed,
            identity_key_sig=parsed.identity_key_sig,
            supports_v2=parsed.supports_v2,
            device_x3dh_pub=parsed.device_x3dh_pub,
            device_sign_pub=parsed.device_sign_pub,
            device_cert_sig=parsed.device_cert_sig,
            client_device_id=client_device_id,
            device_kyber_pub=parsed.device_kyber_pub,
            device_kyber_sig=parsed.device_kyber_sig,
            device_kyber_id=parsed.device_kyber_id,
            created_at=now,
            updated_at=now,
        )
        db.add(bundle)
    else:
        bundle.identity_key = parsed.identity_key
        bundle.signed_prekey = parsed.signed_prekey
        bundle.signed_prekey_sig = parsed.signed_prekey_sig
        bundle.signed_prekey_id = parsed.signed_prekey_id
        bundle.identity_key_ed = parsed.identity_key_ed
        bundle.identity_key_sig = parsed.identity_key_sig
        bundle.supports_v2 = parsed.supports_v2
        bundle.device_x3dh_pub = parsed.device_x3dh_pub
        bundle.device_sign_pub = parsed.device_sign_pub
        bundle.device_cert_sig = parsed.device_cert_sig
        bundle.client_device_id = client_device_id
        bundle.device_kyber_pub = parsed.device_kyber_pub
        bundle.device_kyber_sig = parsed.device_kyber_sig
        bundle.device_kyber_id = parsed.device_kyber_id
        bundle.updated_at = now

    for key_id, public_key in parsed.one_time:
        db.add(
            OneTimePreKey(
                user_id=user.id,
                device_id=device_id,
                key_id=key_id,
                public_key=public_key,
                used=False,
                created_at=now,
            )
        )

    for key_id, public_key in parsed.one_time_kyber:
        db.add(
            OneTimeKyberPreKey(
                user_id=user.id,
                device_id=device_id,
                key_id=key_id,
                public_key=public_key,
                used=False,
                created_at=now,
            )
        )

    db.commit()

    if parsed.identity_key_ed is not None:
        try:
            from app.security.key_backup import _kt_log_account_ed

            _kt_log_account_ed(user.id, parsed.identity_key_ed.hex(), db)
        except Exception as _e:
            logger.debug("KT account_ed log skipped: %s", _e)

    available = _available_opk_count(db, user.id, device_id)

    logger.info(
        "User %d published prekeys (spk_id=%d, new_opk=%d, total_opk=%d)",
        user.id,
        parsed.signed_prekey_id,
        len(parsed.one_time),
        available,
    )

    return PreKeyStatusResponse(**prekey_status_published(bundle.signed_prekey_id, available, bundle.supports_v2))


@router.get("/{user_id}", response_model=PreKeyBundleResponse)
async def get_prekey_bundle(
    user_id: int,
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PreKeyBundleResponse:
    """Retrieves a single Pre-Key Bundle for the specified user.

    Backward-compatible pairwise fetch: returns the most recently updated device
    bundle. НЕ расходует OPK (M4a) — используется для чтения identity/pin;
    установление сессии берёт OPK через POST /{user_id}/claim-opk.
    """
    bundle: Optional[PreKeyBundle] = (
        db.query(PreKeyBundle).filter(PreKeyBundle.user_id == user_id).order_by(PreKeyBundle.updated_at.desc()).first()
    )

    if bundle is None:
        raise HTTPException(
            status_code=404,
            detail=f"Pre-key bundle not found for user {user_id}",
        )

    return PreKeyBundleResponse(**prekey_bundle_response(user_id, _stored(bundle)))


@router.get("/{user_id}/devices", response_model=PreKeyBundleListResponse)
async def get_prekey_bundles_all(
    user_id: int,
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PreKeyBundleListResponse:
    """Discovery: every активный per-device Pre-Key Bundle пользователя (Sesame).

    НЕ расходует OPK (M4a): открытие набора устройств дёргается часто (discovery-
    кэш, TTL) и для устройств с уже установленной сессией — расход OPK за фетч
    дренировал бы пул. OPK берётся ОТДЕЛЬНО на установлении сессии через
    POST /{user_id}/claim-opk (свежий OPK на сессию — forward secrecy). Пустой
    список (не 404) → caller падает в v1 без спец-обработки.
    """
    bundles: list[PreKeyBundle] = (
        db.query(PreKeyBundle).filter(PreKeyBundle.user_id == user_id).order_by(PreKeyBundle.device_id).all()
    )

    return PreKeyBundleListResponse(**prekey_bundle_list(user_id, [_stored(bundle) for bundle in bundles]))


@router.post("/{user_id}/claim-opk", response_model=ClaimOpkResponse)
async def claim_opk(
    user_id: int,
    body: ClaimOpkRequest,
    _user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ClaimOpkResponse:
    """Расходует ОДИН OPK устройства (user_id, device_id) для установления X3DH.

    Единственная точка расхода OPK на приёме бандла (M4a): discovery (/devices,
    /{user_id}) не расходует. Свежий OPK на каждую новую сессию — forward secrecy.
    Нет свободного OPK → {null,null} (X3DH идёт 3-DH без OPK).
    """
    opk_public, opk_key_id = _consume_one_opk(db, user_id, body.device_id)
    kyber_public, kyber_key_id = (None, None)
    if body.want_kyber:
        kyber_public, kyber_key_id = _consume_one_kyber_opk(db, user_id, body.device_id)
    if opk_public is not None or kyber_public is not None:
        db.commit()
    if opk_public is not None:
        remaining = _available_opk_count(db, user_id, body.device_id)
        if prekey_needs_replenishment(remaining):
            logger.warning(
                "User %d device %s has only %d OPKs left — client should replenish",
                user_id,
                body.device_id,
                remaining,
            )
    return ClaimOpkResponse(
        **prekey_claim_response(
            one_time=opk_public,
            one_time_id=opk_key_id,
            one_time_kyber=kyber_public,
            one_time_kyber_id=kyber_key_id,
        )
    )


@router.get("/status/me", response_model=PreKeyStatusResponse)
async def get_prekey_status(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PreKeyStatusResponse:
    """Returns the Pre-Key Bundle status for the current device.

    Scoped to the caller's device (X-Device-Id) so each device self-heals its
    own bundle: another device having published does not make this one skip.
    Useful for the client to determine whether OPK replenishment is needed.
    """
    device_id = _resolve_device_id(request, user.id, db)
    bundle: Optional[PreKeyBundle] = (
        db.query(PreKeyBundle).filter(PreKeyBundle.user_id == user.id, PreKeyBundle.device_id == device_id).first()
    )

    if bundle is None:
        return PreKeyStatusResponse(**prekey_status_unpublished())

    available = _available_opk_count(db, user.id, device_id)

    return PreKeyStatusResponse(**prekey_status_published(bundle.signed_prekey_id, available, bundle.supports_v2))

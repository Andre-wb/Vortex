"""
app/keys/prekeys.py — API for publishing and retrieving Pre-Key Bundles (X3DH / Double Ratchet).

Endpoints:
  POST /api/keys/prekeys/publish   — upload SPK + batch of OPKs.
  GET  /api/keys/prekeys/{user_id} — retrieve Pre-Key Bundle (consumes one OPK).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.config import Config
from app.database import get_db
from app.models import User, UserDevice
from app.models.prekeys import OneTimePreKey, OneTimeKyberPreKey, PreKeyBundle
from app.security.auth_jwt import get_current_user
from app.security.double_ratchet import verify_spk_signature

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/keys/prekeys", tags=["prekeys"])

# Maximum number of OPKs per single publish request.
_MAX_OPK_BATCH = 100

# Minimum recommended OPK reserve; when below this threshold
# the client should replenish the pool.
_LOW_OPK_THRESHOLD = 10


def _validated_client_device_id(request: Request) -> Optional[str]:
    """Return the caller's X-Device-Id header if it is a well-formed 32-hex id."""
    cid = request.headers.get("x-device-id")
    if not cid or not (len(cid) == 32 and all(c in "0123456789abcdef" for c in cid)):
        return None
    return cid


def _resolve_device_id(request: Request, user_id: int, db: Session) -> Optional[int]:
    """Map the caller's X-Device-Id header to a UserDevice.id for this user.

    Returns None when the header is absent/malformed or no matching device row
    exists — the bundle is then stored/looked-up under device_id=NULL (a client
    without a stable device id, or a test client sending no header).
    """
    cid = _validated_client_device_id(request)
    if cid is None:
        return None
    device = (
        db.query(UserDevice)
        .filter(UserDevice.user_id == user_id, UserDevice.client_device_id == cid)
        .first()
    )
    return device.id if device is not None else None


def _consume_one_opk(db: Session, user_id: int, device_id: Optional[int]) -> tuple[Optional[str], Optional[int]]:
    """Mark one unused OPK of (user_id, device_id) as used; return (hex, key_id).

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
    return opk.public_key.hex(), opk.key_id


def _consume_one_kyber_opk(db: Session, user_id: int, device_id: Optional[int]) -> tuple[Optional[str], Optional[int]]:
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
    return pqopk.public_key.hex(), pqopk.key_id


def _device_identity_fields(bundle: PreKeyBundle) -> dict:
    """Device-identity triple + cert + PQXDH Kyber pre-key as hex, for a fetch
    response. Lets the sender recompute (client_device_id ‖ device_x3dh_pub ‖
    device_sign_pub) and verify device_cert_sig against the account identity_key_ed
    at fan-out; device_kyber_sig is verified against device_sign_pub (same chain
    as SPK). Populates both PreKeyBundleResponse and DeviceBundle."""
    return {
        "device_x3dh_pub": bundle.device_x3dh_pub.hex() if bundle.device_x3dh_pub else None,
        "device_sign_pub": bundle.device_sign_pub.hex() if bundle.device_sign_pub else None,
        "device_cert_sig": bundle.device_cert_sig.hex() if bundle.device_cert_sig else None,
        "client_device_id": bundle.client_device_id,
        "device_kyber_pub": bundle.device_kyber_pub.hex() if bundle.device_kyber_pub else None,
        "device_kyber_sig": bundle.device_kyber_sig.hex() if bundle.device_kyber_sig else None,
        "device_kyber_id": bundle.device_kyber_id,
    }


class OneTimePreKeyUpload(BaseModel):
    """A single one-time Pre-Key for upload."""
    key_id: int = Field(..., description="Local OPK identifier (assigned by client)")
    public_key: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="X25519 public key in hex (32 bytes = 64 hex chars)",
    )


class OneTimeKyberPreKeyUpload(BaseModel):
    """A single one-time Kyber Pre-Key (ML-KEM-768) for upload (PQXDH P6)."""
    key_id: int = Field(..., description="Local PQOPK identifier (assigned by client)")
    public_key: str = Field(
        ...,
        min_length=2368,
        max_length=2368,
        description="ML-KEM-768 public key in hex (1184 bytes = 2368 hex chars)",
    )


class PublishPreKeysRequest(BaseModel):
    """Request to publish a Pre-Key Bundle.

    Client sends its Identity Key, Signed Pre-Key (with signature)
    and a batch of One-Time Pre-Keys.
    """
    identity_key: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="X25519 public Identity Key in hex",
    )
    signed_prekey: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="X25519 public Signed Pre-Key in hex",
    )
    signed_prekey_sig: str = Field(
        ...,
        min_length=128,
        max_length=128,
        description="Ed25519 signature of SPK in hex (64 bytes = 128 hex chars)",
    )
    signed_prekey_id: int = Field(
        ...,
        ge=0,
        description="SPK identifier for rotation",
    )
    identity_key_ed: Optional[str] = Field(
        default=None,
        min_length=64,
        max_length=64,
        description="Ed25519 public identity key in hex (used to verify signatures). "
                    "Optional for pre-batch-4 clients.",
    )
    identity_key_sig: Optional[str] = Field(
        default=None,
        min_length=128,
        max_length=128,
        description="Ed25519 signature of the X25519 identity_key, binding it to "
                    "identity_key_ed. Optional for pre-batch-4 clients.",
    )
    supports_v2: Optional[bool] = Field(
        default=None,
        description="Client can RECEIVE v2 Double Ratchet messages.",
    )
    device_x3dh_pub: Optional[str] = Field(
        default=None, min_length=64, max_length=64,
        description="X25519 device X3DH public key in hex (device-identity triple).",
    )
    device_sign_pub: Optional[str] = Field(
        default=None, min_length=64, max_length=64,
        description="Ed25519 device signing public key in hex (device-identity triple).",
    )
    device_cert_sig: Optional[str] = Field(
        default=None, min_length=128, max_length=128,
        description="Ed25519 account signature over (client_device_id ‖ device_x3dh_pub ‖ "
                    "device_sign_pub) in hex. Null when the account Ed25519 is not on this device.",
    )
    device_kyber_pub: Optional[str] = Field(
        default=None, min_length=2368, max_length=2368,
        description="ML-KEM-768 Kyber pre-key public in hex (1184 bytes = 2368 hex). PQXDH.",
    )
    device_kyber_sig: Optional[str] = Field(
        default=None, min_length=128, max_length=128,
        description="Ed25519 signature of device_kyber_pub by device_sign_pub in hex.",
    )
    device_kyber_id: Optional[int] = Field(
        default=None, ge=0, description="Kyber pre-key id for rotation.",
    )
    one_time_prekeys: List[OneTimePreKeyUpload] = Field(
        default_factory=list,
        max_length=_MAX_OPK_BATCH,
        description="Bundle of one-time Pre-Keys (up to 100)",
    )
    one_time_kyber_prekeys: List[OneTimeKyberPreKeyUpload] = Field(
        default_factory=list,
        max_length=_MAX_OPK_BATCH,
        description="Bundle of one-time Kyber Pre-Keys (ML-KEM-768, PQXDH P6)",
    )


class PreKeyBundleResponse(BaseModel):
    """Response with a user's Pre-Key Bundle."""
    user_id: int
    device_id: Optional[int] = None          # device this bundle belongs to, or None
    identity_key: str           # hex
    signed_prekey: str          # hex
    signed_prekey_sig: str      # hex
    signed_prekey_id: int
    identity_key_ed: Optional[str] = None    # hex Ed25519 identity pub or None
    identity_key_sig: Optional[str] = None   # hex Ed25519 sig of identity_key or None
    supports_v2: Optional[bool] = None       # peer can receive v2 Double Ratchet
    # Device-identity triple (public parts) — forward-looking, verified at fan-out.
    device_x3dh_pub: Optional[str] = None    # hex X25519 device X3DH pub
    device_sign_pub: Optional[str] = None    # hex Ed25519 device signing pub
    device_cert_sig: Optional[str] = None    # hex Ed25519 account cert over the triple
    client_device_id: Optional[str] = None   # id signed inside the cert
    device_kyber_pub: Optional[str] = None   # hex ML-KEM-768 Kyber pre-key pub (PQXDH)
    device_kyber_sig: Optional[str] = None   # hex Ed25519 sig of kyber pub by device_sign_pub
    device_kyber_id: Optional[int] = None    # Kyber pre-key id
    one_time_prekey: Optional[str] = None   # hex — single OPK or None
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
    bundles: List[DeviceBundle]


class ClaimOpkRequest(BaseModel):
    """Claim one OPK of a specific device for X3DH establishment."""
    device_id: Optional[int] = None   # UserDevice.id бандла; None → device_id IS NULL
    want_kyber: bool = False          # также израсходовать PQOPK (PQXDH P6) — только если сессия идёт в PQ


class ClaimOpkResponse(BaseModel):
    one_time_prekey: Optional[str] = None      # hex или None (пул пуст)
    one_time_prekey_id: Optional[int] = None
    one_time_kyber_prekey: Optional[str] = None       # ML-KEM-768 pub hex или None (PQXDH P6)
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
    """
    try:
        ik_bytes = bytes.fromhex(body.identity_key)
        spk_bytes = bytes.fromhex(body.signed_prekey)
        sig_bytes = bytes.fromhex(body.signed_prekey_sig)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex encoding in keys")

    if len(ik_bytes) != 32 or len(spk_bytes) != 32 or len(sig_bytes) != 64:
        raise HTTPException(status_code=400, detail="Invalid key lengths")

    # Ed25519 identity key + binding signature. Verify BEFORE
    # any db write so a rejected bundle never partially persists. Config flag is
    # read at call time so tests can toggle enforce/warn.
    ik_ed_bytes: Optional[bytes] = None
    ik_sig_bytes: Optional[bytes] = None
    if body.identity_key_ed is not None:
        try:
            ik_ed_bytes = bytes.fromhex(body.identity_key_ed)
            if body.identity_key_sig is not None:
                ik_sig_bytes = bytes.fromhex(body.identity_key_sig)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid hex encoding in identity key/signature")
        if len(ik_ed_bytes) != 32 or (ik_sig_bytes is not None and len(ik_sig_bytes) != 64):
            raise HTTPException(status_code=400, detail="Invalid identity key/signature lengths")

    def _sig_error(detail: str) -> None:
        """Enforce → 400; warn-only → log and continue (safe rollout)."""
        if Config.PREKEY_SIG_ENFORCE:
            raise HTTPException(status_code=400, detail=detail)
        logger.warning("User %d prekey publish: %s (warn-only, accepted)", user.id, detail)

    if ik_ed_bytes is not None:
        ed_pub = Ed25519PublicKey.from_public_bytes(ik_ed_bytes)
        # SPK signature: authenticates the Signed Pre-Key under the Ed25519 identity.
        if not verify_spk_signature(ed_pub, spk_bytes, sig_bytes):
            _sig_error("Signed pre-key signature verification failed")
        # Identity-binding signature: Ed25519 identity signs the X25519 identity_key.
        if ik_sig_bytes is None:
            _sig_error("Missing identity_key_sig binding signature")
        elif not verify_spk_signature(ed_pub, ik_bytes, ik_sig_bytes):
            _sig_error("Identity-key binding signature verification failed")
    else:
        # No Ed25519 key at all — nothing to verify against (pre-batch-4 client).
        _sig_error("No Ed25519 identity key provided — signature cannot be verified")

    # Device-identity triple (public parts) + account cert over it. Forward-
    # looking: stored now, verified/used at fan-out. Length-check here so a
    # malformed publish is rejected before any db write. Cert signature is NOT
    # verified here — that is the sender's job at fan-out, against the account
    # Ed25519 the sender trusts out-of-band.
    dev_x3dh_bytes: Optional[bytes] = None
    dev_sign_bytes: Optional[bytes] = None
    dev_cert_bytes: Optional[bytes] = None
    try:
        if body.device_x3dh_pub is not None:
            dev_x3dh_bytes = bytes.fromhex(body.device_x3dh_pub)
        if body.device_sign_pub is not None:
            dev_sign_bytes = bytes.fromhex(body.device_sign_pub)
        if body.device_cert_sig is not None:
            dev_cert_bytes = bytes.fromhex(body.device_cert_sig)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex encoding in device-identity fields")
    if (dev_x3dh_bytes is not None and len(dev_x3dh_bytes) != 32) \
            or (dev_sign_bytes is not None and len(dev_sign_bytes) != 32) \
            or (dev_cert_bytes is not None and len(dev_cert_bytes) != 64):
        raise HTTPException(status_code=400, detail="Invalid device-identity field lengths")

    # PQXDH per-device Kyber pre-key (ML-KEM-768). Public подписан device
    # signing-ключом — проверяем против device_sign_pub (та же цепочка, что SPK
    # на fan-out: _bundleWellSigned; НЕ против identity_key_ed). Verify только при
    # наличии device_sign_pub (no-device путь — pre-key не таргет P5, хранится как
    # device_cert_sig без проверки). Length-check до записи.
    dev_kyber_bytes: Optional[bytes] = None
    dev_kyber_sig_bytes: Optional[bytes] = None
    try:
        if body.device_kyber_pub is not None:
            dev_kyber_bytes = bytes.fromhex(body.device_kyber_pub)
        if body.device_kyber_sig is not None:
            dev_kyber_sig_bytes = bytes.fromhex(body.device_kyber_sig)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex encoding in Kyber pre-key fields")
    if (dev_kyber_bytes is not None and len(dev_kyber_bytes) != 1184) \
            or (dev_kyber_sig_bytes is not None and len(dev_kyber_sig_bytes) != 64):
        raise HTTPException(status_code=400, detail="Invalid Kyber pre-key field lengths")
    if dev_kyber_bytes is not None and dev_sign_bytes is not None:
        dev_sign_ed = Ed25519PublicKey.from_public_bytes(dev_sign_bytes)
        if dev_kyber_sig_bytes is None:
            _sig_error("Missing device_kyber_sig for Kyber pre-key")
        elif not verify_spk_signature(dev_sign_ed, dev_kyber_bytes, dev_kyber_sig_bytes):
            _sig_error("Kyber pre-key signature verification failed")

    # Upsert PreKeyBundle for the publishing device (device_id=NULL for a client
    # without a stable device id). filter(device_id == None) → IS NULL in SQL.
    device_id = _resolve_device_id(request, user.id, db)
    client_device_id = _validated_client_device_id(request)
    bundle: Optional[PreKeyBundle] = (
        db.query(PreKeyBundle)
        .filter(PreKeyBundle.user_id == user.id, PreKeyBundle.device_id == device_id)
        .first()
    )

    now = datetime.now(timezone.utc)

    if bundle is None:
        bundle = PreKeyBundle(
            user_id=user.id,
            device_id=device_id,
            identity_key=ik_bytes,
            signed_prekey=spk_bytes,
            signed_prekey_sig=sig_bytes,
            signed_prekey_id=body.signed_prekey_id,
            identity_key_ed=ik_ed_bytes,
            identity_key_sig=ik_sig_bytes,
            supports_v2=body.supports_v2,
            device_x3dh_pub=dev_x3dh_bytes,
            device_sign_pub=dev_sign_bytes,
            device_cert_sig=dev_cert_bytes,
            client_device_id=client_device_id,
            device_kyber_pub=dev_kyber_bytes,
            device_kyber_sig=dev_kyber_sig_bytes,
            device_kyber_id=body.device_kyber_id,
            created_at=now,
            updated_at=now,
        )
        db.add(bundle)
    else:
        bundle.identity_key = ik_bytes
        bundle.signed_prekey = spk_bytes
        bundle.signed_prekey_sig = sig_bytes
        bundle.signed_prekey_id = body.signed_prekey_id
        bundle.identity_key_ed = ik_ed_bytes
        bundle.identity_key_sig = ik_sig_bytes
        bundle.supports_v2 = body.supports_v2
        bundle.device_x3dh_pub = dev_x3dh_bytes
        bundle.device_sign_pub = dev_sign_bytes
        bundle.device_cert_sig = dev_cert_bytes
        bundle.client_device_id = client_device_id
        bundle.device_kyber_pub = dev_kyber_bytes
        bundle.device_kyber_sig = dev_kyber_sig_bytes
        bundle.device_kyber_id = body.device_kyber_id
        bundle.updated_at = now

    # Add one-time keys
    for opk in body.one_time_prekeys:
        try:
            opk_bytes = bytes.fromhex(opk.public_key)
        except ValueError:
            logger.warning("Skipping OPK with invalid hex, key_id=%d", opk.key_id)
            continue
        if len(opk_bytes) != 32:
            logger.warning("Skipping OPK with wrong length, key_id=%d", opk.key_id)
            continue

        db.add(OneTimePreKey(
            user_id=user.id,
            device_id=device_id,
            key_id=opk.key_id,
            public_key=opk_bytes,
            used=False,
            created_at=now,
        ))

    # One-time Kyber pre-keys (ML-KEM-768, PQXDH P6) — тот же upsert-путь.
    for pqopk in body.one_time_kyber_prekeys:
        try:
            pqopk_bytes = bytes.fromhex(pqopk.public_key)
        except ValueError:
            logger.warning("Skipping PQOPK with invalid hex, key_id=%d", pqopk.key_id)
            continue
        if len(pqopk_bytes) != 1184:
            logger.warning("Skipping PQOPK with wrong length, key_id=%d", pqopk.key_id)
            continue
        db.add(OneTimeKyberPreKey(
            user_id=user.id,
            device_id=device_id,
            key_id=pqopk.key_id,
            public_key=pqopk_bytes,
            used=False,
            created_at=now,
        ))

    db.commit()

    # Count this device's available OPKs
    available = (
        db.query(OneTimePreKey)
        .filter(
            OneTimePreKey.user_id == user.id,
            OneTimePreKey.device_id == device_id,
            OneTimePreKey.used == False,  # noqa: E712
        )
        .count()
    )

    logger.info(
        "User %d published prekeys (spk_id=%d, new_opk=%d, total_opk=%d)",
        user.id, body.signed_prekey_id, len(body.one_time_prekeys), available,
    )

    return PreKeyStatusResponse(
        published=True,
        signed_prekey_id=bundle.signed_prekey_id,
        available_opk_count=available,
        low_opk_warning=available < _LOW_OPK_THRESHOLD,
        supports_v2=bundle.supports_v2,
    )


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
        db.query(PreKeyBundle)
        .filter(PreKeyBundle.user_id == user_id)
        .order_by(PreKeyBundle.updated_at.desc())
        .first()
    )

    if bundle is None:
        raise HTTPException(
            status_code=404,
            detail=f"Pre-key bundle not found for user {user_id}",
        )

    return PreKeyBundleResponse(
        user_id=user_id,
        device_id=bundle.device_id,
        identity_key=bundle.identity_key.hex(),
        signed_prekey=bundle.signed_prekey.hex(),
        signed_prekey_sig=bundle.signed_prekey_sig.hex(),
        signed_prekey_id=bundle.signed_prekey_id,
        identity_key_ed=bundle.identity_key_ed.hex() if bundle.identity_key_ed else None,
        identity_key_sig=bundle.identity_key_sig.hex() if bundle.identity_key_sig else None,
        supports_v2=bundle.supports_v2,
        one_time_prekey=None,        # discovery не выдаёт OPK — см. /claim-opk
        one_time_prekey_id=None,
        **_device_identity_fields(bundle),
    )


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
    bundles: List[PreKeyBundle] = (
        db.query(PreKeyBundle)
        .filter(PreKeyBundle.user_id == user_id)
        .order_by(PreKeyBundle.device_id)
        .all()
    )

    out = [
        DeviceBundle(
            device_id=bundle.device_id,
            identity_key=bundle.identity_key.hex(),
            signed_prekey=bundle.signed_prekey.hex(),
            signed_prekey_sig=bundle.signed_prekey_sig.hex(),
            signed_prekey_id=bundle.signed_prekey_id,
            identity_key_ed=bundle.identity_key_ed.hex() if bundle.identity_key_ed else None,
            identity_key_sig=bundle.identity_key_sig.hex() if bundle.identity_key_sig else None,
            supports_v2=bundle.supports_v2,
            one_time_prekey=None,        # discovery не выдаёт OPK — см. /claim-opk
            one_time_prekey_id=None,
            **_device_identity_fields(bundle),
        )
        for bundle in bundles
    ]
    return PreKeyBundleListResponse(user_id=user_id, bundles=out)


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
    opk_hex, opk_key_id = _consume_one_opk(db, user_id, body.device_id)
    # PQOPK — расходуем ТОЛЬКО когда сессия реально идёт в PQ (want_kyber), иначе
    # не-PQ трафик (флаг-off отправители = дефолт) выжигал бы пул → фича не срабатывала бы.
    kyber_hex, kyber_key_id = (None, None)
    if body.want_kyber:
        kyber_hex, kyber_key_id = _consume_one_kyber_opk(db, user_id, body.device_id)
    if opk_hex is not None or kyber_hex is not None:
        db.commit()
    if opk_hex is not None:
        remaining = (
            db.query(OneTimePreKey)
            .filter(
                OneTimePreKey.user_id == user_id,
                OneTimePreKey.device_id == body.device_id,
                OneTimePreKey.used == False,  # noqa: E712
            )
            .count()
        )
        if remaining < _LOW_OPK_THRESHOLD:
            logger.warning(
                "User %d device %s has only %d OPKs left — client should replenish",
                user_id, body.device_id, remaining,
            )
    return ClaimOpkResponse(
        one_time_prekey=opk_hex, one_time_prekey_id=opk_key_id,
        one_time_kyber_prekey=kyber_hex, one_time_kyber_prekey_id=kyber_key_id,
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
        db.query(PreKeyBundle)
        .filter(PreKeyBundle.user_id == user.id, PreKeyBundle.device_id == device_id)
        .first()
    )

    if bundle is None:
        return PreKeyStatusResponse(
            published=False,
            available_opk_count=0,
            low_opk_warning=True,
        )

    available = (
        db.query(OneTimePreKey)
        .filter(
            OneTimePreKey.user_id == user.id,
            OneTimePreKey.device_id == device_id,
            OneTimePreKey.used == False,  # noqa: E712
        )
        .count()
    )

    return PreKeyStatusResponse(
        published=True,
        signed_prekey_id=bundle.signed_prekey_id,
        available_opk_count=available,
        low_opk_warning=available < _LOW_OPK_THRESHOLD,
        supports_v2=bundle.supports_v2,
    )

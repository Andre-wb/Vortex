"""Независимая Python-реализация правил pre-key бандла Vortex.

Не продуктовый код и не снимок прошлой реализации: это вторая, независимо
написанная реализация формата, против которой сверяется крейт `vortex-proto`.
Правила:

    hex            = строго пары [0-9a-fA-F], пробелы не игнорируются
    ключи бандла   = X25519 32 байта, Ed25519 32 байта, подпись 64 байта,
                     ML-KEM-768 1184 байта
    порядок отказа = форма (идентификаторы, пределы пачек) → ключи аккаунта →
                     Ed25519-идентичность → подписи → устройство → Kyber →
                     одноразовые ключи
    подписи        = SPK подписан аккаунтным Ed25519, identity_key им же,
                     Kyber pre-key — ключом подписи устройства
    ответ          = те же поля в hex; одноразовый ключ в бандл не кладётся
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

X25519_PUBLIC_LEN = 32
ED25519_PUBLIC_LEN = 32
ED25519_SIGNATURE_LEN = 64
KYBER_PUBLIC_LEN = 1184
CLIENT_DEVICE_ID_LEN = 32
MAX_ONE_TIME_BATCH = 100
LOW_ONE_TIME_THRESHOLD = 10

_HEX_DIGITS = set("0123456789abcdefABCDEF")


class NotHexError(Exception):
    pass


class WrongLengthError(Exception):
    pass


def decode_hex(text: str) -> bytes:
    if len(text) % 2 != 0:
        raise NotHexError()
    if any(character not in _HEX_DIGITS for character in text):
        raise NotHexError()
    return bytes.fromhex(text)


def decode_fixed(text: str, expected: int) -> bytes:
    raw = decode_hex(text)
    if len(raw) != expected:
        raise WrongLengthError()
    return raw


def encode_hex(raw: Optional[bytes]) -> Optional[str]:
    return None if raw is None else raw.hex()


_FIELD = 2**255 - 19
_CURVE_D = (-121665 * pow(121666, _FIELD - 2, _FIELD)) % _FIELD
_SQRT_MINUS_ONE = pow(2, (_FIELD - 1) // 4, _FIELD)
_IDENTITY = (0, 1)


def _sqrt_ratio(u: int, v: int) -> Optional[int]:
    candidate = u * pow(v, 3, _FIELD) % _FIELD
    candidate = candidate * pow(u * pow(v, 7, _FIELD) % _FIELD, (_FIELD - 5) // 8, _FIELD) % _FIELD
    if v * candidate * candidate % _FIELD == u % _FIELD:
        return candidate
    if v * candidate * candidate % _FIELD == (-u) % _FIELD:
        return candidate * _SQRT_MINUS_ONE % _FIELD
    return None


def decompress(raw: bytes) -> Optional[tuple[int, int]]:
    """Точка кривой из канонической кодировки; None — неканонично или не точка."""
    value = int.from_bytes(raw, "little")
    sign = (value >> 255) & 1
    y = value & ((1 << 255) - 1)
    if y >= _FIELD:
        return None
    x = _sqrt_ratio((y * y - 1) % _FIELD, (_CURVE_D * y * y + 1) % _FIELD)
    if x is None:
        return None
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = (-x) % _FIELD
    return (x, y)


def _add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = _CURVE_D * x1 * x2 * y1 * y2 % _FIELD
    x3 = (x1 * y2 + x2 * y1) * pow(1 + product, _FIELD - 2, _FIELD) % _FIELD
    y3 = (y1 * y2 + x1 * x2) * pow(1 - product, _FIELD - 2, _FIELD) % _FIELD
    return (x3, y3)


def is_small_order(point: tuple[int, int]) -> bool:
    """Точка малого порядка — та, что умножением на кофактор 8 даёт нейтральную."""
    doubled = point
    for _ in range(3):
        doubled = _add(doubled, doubled)
    return doubled == _IDENTITY


def usable(raw: bytes) -> bool:
    """Ключ годен, если кодировка канонична и точка не малого порядка."""
    point = decompress(raw)
    return point is not None and not is_small_order(point)


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if not usable(public) or not usable(signature[:ED25519_PUBLIC_LEN]):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        return True
    except Exception:
        return False


def _reject(detail: str) -> dict:
    return {"rejection": {"status": 400, "detail": detail}}


def _group(values: list[Optional[str]], sizes: list[int], hex_detail: str, length_detail: str):
    raw: list[Optional[bytes]] = []
    for value in values:
        if value is None:
            raw.append(None)
            continue
        try:
            raw.append(decode_hex(value))
        except NotHexError:
            raise _RefusedError(hex_detail) from None
    for item, size in zip(raw, sizes, strict=True):
        if item is not None and len(item) != size:
            raise _RefusedError(length_detail) from None
    return raw


class _RefusedError(Exception):
    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


def parse_publish(payload: dict, enforce: bool) -> dict:
    try:
        return _parse_publish(payload, enforce)
    except _RefusedError as refused:
        return _reject(refused.detail)


def _parse_publish(payload: dict, enforce: bool) -> dict:
    complaints: list[str] = []

    def complain(detail: str) -> None:
        if enforce:
            raise _RefusedError(detail)
        complaints.append(detail)

    signed_prekey_id = payload["signed_prekey_id"]
    if signed_prekey_id < 0:
        raise _RefusedError("Invalid signed_prekey_id")
    kyber_id = payload.get("device_kyber_id")
    if kyber_id is not None and kyber_id < 0:
        raise _RefusedError("Invalid device_kyber_id")
    one_time = payload.get("one_time_prekeys") or []
    one_time_kyber = payload.get("one_time_kyber_prekeys") or []
    if len(one_time) > MAX_ONE_TIME_BATCH:
        raise _RefusedError(f"At most {MAX_ONE_TIME_BATCH} one-time pre-keys per publish")
    if len(one_time_kyber) > MAX_ONE_TIME_BATCH:
        raise _RefusedError(f"At most {MAX_ONE_TIME_BATCH} one-time Kyber pre-keys per publish")

    identity_key, signed_prekey, signed_prekey_sig = _group(
        [payload["identity_key"], payload["signed_prekey"], payload["signed_prekey_sig"]],
        [X25519_PUBLIC_LEN, X25519_PUBLIC_LEN, ED25519_SIGNATURE_LEN],
        "Invalid hex encoding in keys",
        "Invalid key lengths",
    )

    identity_key_ed = payload.get("identity_key_ed")
    identity_key_sig = payload.get("identity_key_sig")
    if identity_key_ed is None:
        account_ed, account_sig = None, None
    else:
        account_ed, account_sig = _group(
            [identity_key_ed, identity_key_sig],
            [ED25519_PUBLIC_LEN, ED25519_SIGNATURE_LEN],
            "Invalid hex encoding in identity key/signature",
            "Invalid identity key/signature lengths",
        )

    if account_ed is None:
        complain("No Ed25519 identity key provided — signature cannot be verified")
    else:
        if not usable(account_ed):
            raise _RefusedError("Unusable Ed25519 identity key")
        if not verify(account_ed, signed_prekey, signed_prekey_sig):
            complain("Signed pre-key signature verification failed")
        if account_sig is None:
            complain("Missing identity_key_sig binding signature")
        elif not verify(account_ed, identity_key, account_sig):
            complain("Identity-key binding signature verification failed")

    device_x3dh, device_sign, device_cert = _group(
        [payload.get("device_x3dh_pub"), payload.get("device_sign_pub"), payload.get("device_cert_sig")],
        [X25519_PUBLIC_LEN, ED25519_PUBLIC_LEN, ED25519_SIGNATURE_LEN],
        "Invalid hex encoding in device-identity fields",
        "Invalid device-identity field lengths",
    )

    if device_sign is not None and not usable(device_sign):
        raise _RefusedError("Unusable device signing key")

    kyber_public, kyber_sig = _group(
        [payload.get("device_kyber_pub"), payload.get("device_kyber_sig")],
        [KYBER_PUBLIC_LEN, ED25519_SIGNATURE_LEN],
        "Invalid hex encoding in Kyber pre-key fields",
        "Invalid Kyber pre-key field lengths",
    )

    if kyber_public is not None and device_sign is not None:
        if kyber_sig is None:
            complain("Missing device_kyber_sig for Kyber pre-key")
        elif not verify(device_sign, kyber_public, kyber_sig):
            complain("Kyber pre-key signature verification failed")

    accepted_one_time = _collect(one_time, X25519_PUBLIC_LEN, "one-time pre-key")
    accepted_kyber = _collect(one_time_kyber, KYBER_PUBLIC_LEN, "one-time Kyber pre-key")

    return {
        "accepted": {
            "identity_key": identity_key.hex(),
            "signed_prekey": signed_prekey.hex(),
            "signed_prekey_sig": signed_prekey_sig.hex(),
            "signed_prekey_id": signed_prekey_id,
            "identity_key_ed": encode_hex(account_ed),
            "identity_key_sig": encode_hex(account_sig),
            "supports_v2": payload.get("supports_v2"),
            "device_x3dh_pub": encode_hex(device_x3dh),
            "device_sign_pub": encode_hex(device_sign),
            "device_cert_sig": encode_hex(device_cert),
            "device_kyber_pub": encode_hex(kyber_public),
            "device_kyber_sig": encode_hex(kyber_sig),
            "device_kyber_id": kyber_id,
            "one_time": accepted_one_time,
            "one_time_kyber": accepted_kyber,
            "complaints": complaints,
        }
    }


def _collect(uploads: list, size: int, label: str) -> list:
    out = []
    for upload in uploads:
        key_id = upload["key_id"]
        try:
            public = decode_fixed(upload["public_key"], size)
        except NotHexError:
            raise _RefusedError(f"Invalid hex encoding in {label}, key_id={key_id}") from None
        except WrongLengthError:
            raise _RefusedError(f"Invalid {label} length, key_id={key_id}") from None
        out.append([key_id, public.hex()])
    return out


def device_bundle(stored: dict) -> dict:
    return {
        "device_id": stored.get("device_id"),
        "identity_key": stored["identity_key"],
        "signed_prekey": stored["signed_prekey"],
        "signed_prekey_sig": stored["signed_prekey_sig"],
        "signed_prekey_id": stored["signed_prekey_id"],
        "identity_key_ed": stored.get("identity_key_ed"),
        "identity_key_sig": stored.get("identity_key_sig"),
        "supports_v2": stored.get("supports_v2"),
        "device_x3dh_pub": stored.get("device_x3dh_pub"),
        "device_sign_pub": stored.get("device_sign_pub"),
        "device_cert_sig": stored.get("device_cert_sig"),
        "client_device_id": stored.get("client_device_id"),
        "device_kyber_pub": stored.get("device_kyber_pub"),
        "device_kyber_sig": stored.get("device_kyber_sig"),
        "device_kyber_id": stored.get("device_kyber_id"),
        "one_time_prekey": None,
        "one_time_prekey_id": None,
    }


def bundle_response(user_id: int, stored: dict) -> dict:
    return {"user_id": user_id, **device_bundle(stored)}


def bundle_list(user_id: int, stored: list) -> dict:
    return {"user_id": user_id, "bundles": [device_bundle(entry) for entry in stored]}


def claim_response(
    one_time: Optional[str],
    one_time_id: Optional[int],
    one_time_kyber: Optional[str],
    one_time_kyber_id: Optional[int],
) -> dict:
    classic = one_time is not None and one_time_id is not None
    quantum = one_time_kyber is not None and one_time_kyber_id is not None
    return {
        "one_time_prekey": one_time if classic else None,
        "one_time_prekey_id": one_time_id if classic else None,
        "one_time_kyber_prekey": one_time_kyber if quantum else None,
        "one_time_kyber_prekey_id": one_time_kyber_id if quantum else None,
    }


def status(published: bool, signed_prekey_id: Optional[int], available: int, supports_v2: Optional[bool]) -> dict:
    if not published:
        return {
            "published": False,
            "signed_prekey_id": None,
            "available_opk_count": 0,
            "low_opk_warning": True,
            "supports_v2": None,
        }
    return {
        "published": True,
        "signed_prekey_id": signed_prekey_id,
        "available_opk_count": available,
        "low_opk_warning": available < LOW_ONE_TIME_THRESHOLD,
        "supports_v2": supports_v2,
    }


def client_device_id(header: Optional[str]) -> Optional[str]:
    if header is None or len(header) != CLIENT_DEVICE_ID_LEN:
        return None
    if any(character not in "0123456789abcdef" for character in header):
        return None
    return header


@dataclass(frozen=True)
class ParityFunction:
    name: str
    python: Callable[[dict], object]
    cases: list[dict]


def _publish_case(args: dict):
    return parse_publish(args["payload"], args["enforce"])


def _bundle_response_case(args: dict):
    return bundle_response(args["user_id"], args["stored"])


def _bundle_list_case(args: dict):
    return bundle_list(args["user_id"], args["stored"])


def _claim_case(args: dict):
    return claim_response(
        args.get("one_time"),
        args.get("one_time_id"),
        args.get("one_time_kyber"),
        args.get("one_time_kyber_id"),
    )


def _status_case(args: dict):
    return status(args["published"], args.get("signed_prekey_id"), args["available"], args.get("supports_v2"))


def _device_id_case(args: dict):
    return {"client_device_id": client_device_id(args.get("header"))}


ACCOUNT_SEED = bytes(range(32))
DEVICE_SEED = bytes(range(32, 64))

_account = Ed25519PrivateKey.from_private_bytes(ACCOUNT_SEED)
_device = Ed25519PrivateKey.from_private_bytes(DEVICE_SEED)

ACCOUNT_ED = _account.public_key().public_bytes_raw().hex()
DEVICE_SIGN = _device.public_key().public_bytes_raw().hex()

IDENTITY_KEY = "11" * X25519_PUBLIC_LEN
SIGNED_PREKEY = "22" * X25519_PUBLIC_LEN
KYBER_PUBLIC = "33" * KYBER_PUBLIC_LEN
CLIENT_DEVICE_ID = "0123456789abcdef0123456789abcdef"

SPK_SIG = _account.sign(bytes.fromhex(SIGNED_PREKEY)).hex()
IDENTITY_SIG = _account.sign(bytes.fromhex(IDENTITY_KEY)).hex()
KYBER_SIG = _device.sign(bytes.fromhex(KYBER_PUBLIC)).hex()
KYBER_SIG_BY_ACCOUNT = _account.sign(bytes.fromhex(KYBER_PUBLIC)).hex()

NON_CANONICAL_SIG = SPK_SIG[:96] + "ff" * 16
NON_CANONICAL_R = "ff" * ED25519_PUBLIC_LEN + SPK_SIG[ED25519_PUBLIC_LEN * 2 :]
SMALL_ORDER_R = "00" * ED25519_PUBLIC_LEN + SPK_SIG[ED25519_PUBLIC_LEN * 2 :]
SMALL_ORDER_ED = "00" * ED25519_PUBLIC_LEN
NON_CANONICAL_ED = "ff" * ED25519_PUBLIC_LEN
ZERO_SIG = "00" * ED25519_SIGNATURE_LEN
FORGED_IDENTITY_KEY = "00" * 31 + "03"
FORGED_SIGNED_PREKEY = "00" * 31 + "04"


def _bundle(**overrides) -> dict:
    payload = {
        "identity_key": IDENTITY_KEY,
        "signed_prekey": SIGNED_PREKEY,
        "signed_prekey_sig": SPK_SIG,
        "signed_prekey_id": 1,
        "identity_key_ed": ACCOUNT_ED,
        "identity_key_sig": IDENTITY_SIG,
        "supports_v2": True,
    }
    payload.update(overrides)
    return payload


def _with_kyber(**overrides) -> dict:
    payload = _bundle(
        device_x3dh_pub="44" * X25519_PUBLIC_LEN,
        device_sign_pub=DEVICE_SIGN,
        device_cert_sig="55" * ED25519_SIGNATURE_LEN,
        device_kyber_pub=KYBER_PUBLIC,
        device_kyber_sig=KYBER_SIG,
        device_kyber_id=0,
    )
    payload.update(overrides)
    return payload


STORED_FULL = {
    "device_id": 4,
    "identity_key": IDENTITY_KEY,
    "signed_prekey": SIGNED_PREKEY,
    "signed_prekey_sig": SPK_SIG,
    "signed_prekey_id": 3,
    "identity_key_ed": ACCOUNT_ED,
    "identity_key_sig": IDENTITY_SIG,
    "supports_v2": True,
    "device_x3dh_pub": "44" * X25519_PUBLIC_LEN,
    "device_sign_pub": DEVICE_SIGN,
    "device_cert_sig": "55" * ED25519_SIGNATURE_LEN,
    "client_device_id": CLIENT_DEVICE_ID,
    "device_kyber_pub": KYBER_PUBLIC,
    "device_kyber_sig": KYBER_SIG,
    "device_kyber_id": 0,
}

STORED_BARE = {
    "device_id": None,
    "identity_key": IDENTITY_KEY,
    "signed_prekey": SIGNED_PREKEY,
    "signed_prekey_sig": SPK_SIG,
    "signed_prekey_id": 0,
    "identity_key_ed": None,
    "identity_key_sig": None,
    "supports_v2": None,
    "device_x3dh_pub": None,
    "device_sign_pub": None,
    "device_cert_sig": None,
    "client_device_id": None,
    "device_kyber_pub": None,
    "device_kyber_sig": None,
    "device_kyber_id": None,
}

FUNCTIONS = [
    ParityFunction(
        name="publish_parse",
        python=_publish_case,
        cases=[
            {"payload": _bundle(), "enforce": True},
            {"payload": _bundle(), "enforce": False},
            {"payload": _with_kyber(), "enforce": True},
            {"payload": _bundle(supports_v2=None), "enforce": True},
            {"payload": _bundle(identity_key_ed=None, identity_key_sig=None), "enforce": False},
            {"payload": _bundle(identity_key_ed=None, identity_key_sig=None), "enforce": True},
            {"payload": _bundle(identity_key_sig=None), "enforce": False},
            {"payload": _bundle(identity_key_sig=None), "enforce": True},
            {"payload": _bundle(signed_prekey_sig="00" * ED25519_SIGNATURE_LEN), "enforce": False},
            {"payload": _bundle(signed_prekey_sig="00" * ED25519_SIGNATURE_LEN), "enforce": True},
            {"payload": _bundle(identity_key_sig=SPK_SIG), "enforce": False},
            {"payload": _bundle(signed_prekey_sig=NON_CANONICAL_SIG), "enforce": False},
            {"payload": _bundle(signed_prekey_sig=NON_CANONICAL_R), "enforce": False},
            {"payload": _bundle(signed_prekey_sig=SMALL_ORDER_R), "enforce": False},
            {"payload": _bundle(identity_key_ed=SMALL_ORDER_ED), "enforce": False},
            {"payload": _bundle(identity_key_ed=NON_CANONICAL_ED), "enforce": False},
            {"payload": _with_kyber(device_sign_pub=SMALL_ORDER_ED), "enforce": False},
            {"payload": _bundle(device_sign_pub=NON_CANONICAL_ED), "enforce": False},
            {
                "payload": _bundle(
                    identity_key=FORGED_IDENTITY_KEY,
                    signed_prekey=FORGED_SIGNED_PREKEY,
                    identity_key_ed=SMALL_ORDER_ED,
                    identity_key_sig=ZERO_SIG,
                    signed_prekey_sig=ZERO_SIG,
                ),
                "enforce": False,
            },
            {
                "payload": _bundle(
                    identity_key=FORGED_IDENTITY_KEY,
                    signed_prekey=FORGED_SIGNED_PREKEY,
                    identity_key_ed=SMALL_ORDER_ED,
                    identity_key_sig=ZERO_SIG,
                    signed_prekey_sig=ZERO_SIG,
                ),
                "enforce": True,
            },
            {"payload": _bundle(identity_key="zz" * X25519_PUBLIC_LEN), "enforce": True},
            {"payload": _bundle(identity_key="11" * 31), "enforce": True},
            {"payload": _bundle(identity_key="11 " * 31 + "11"), "enforce": True},
            {"payload": _bundle(signed_prekey="22" * 33), "enforce": True},
            {"payload": _bundle(signed_prekey_sig="ab"), "enforce": True},
            {"payload": _bundle(identity_key_ed="zz" * ED25519_PUBLIC_LEN), "enforce": True},
            {"payload": _bundle(identity_key_ed="aa" * 31), "enforce": True},
            {"payload": _bundle(identity_key_sig="aa" * 63), "enforce": True},
            {"payload": _bundle(signed_prekey_id=-1), "enforce": True},
            {"payload": _bundle(signed_prekey_id=0), "enforce": True},
            {"payload": _with_kyber(device_kyber_id=-1), "enforce": True},
            {"payload": _bundle(device_x3dh_pub="zz" * X25519_PUBLIC_LEN), "enforce": True},
            {"payload": _bundle(device_sign_pub="aa" * 31), "enforce": True},
            {"payload": _bundle(device_cert_sig="aa" * 65), "enforce": True},
            {"payload": _with_kyber(device_kyber_pub="zz" * KYBER_PUBLIC_LEN), "enforce": True},
            {"payload": _with_kyber(device_kyber_pub="33" * 1183), "enforce": True},
            {"payload": _with_kyber(device_kyber_sig="aa" * 63), "enforce": True},
            {"payload": _with_kyber(device_kyber_sig=None), "enforce": False},
            {"payload": _with_kyber(device_kyber_sig=None), "enforce": True},
            {"payload": _with_kyber(device_kyber_sig=KYBER_SIG_BY_ACCOUNT), "enforce": False},
            {"payload": _with_kyber(device_sign_pub=None, device_kyber_sig=None), "enforce": True},
            {
                "payload": _bundle(
                    one_time_prekeys=[
                        {"key_id": 1, "public_key": "66" * X25519_PUBLIC_LEN},
                        {"key_id": 2, "public_key": "77" * X25519_PUBLIC_LEN},
                    ]
                ),
                "enforce": True,
            },
            {
                "payload": _bundle(one_time_prekeys=[{"key_id": 9, "public_key": "zz" * X25519_PUBLIC_LEN}]),
                "enforce": True,
            },
            {
                "payload": _bundle(one_time_prekeys=[{"key_id": 8, "public_key": "66" * 31}]),
                "enforce": True,
            },
            {
                "payload": _bundle(
                    one_time_prekeys=[
                        {"key_id": index, "public_key": "66" * X25519_PUBLIC_LEN}
                        for index in range(MAX_ONE_TIME_BATCH + 1)
                    ]
                ),
                "enforce": True,
            },
            {
                "payload": _bundle(one_time_kyber_prekeys=[{"key_id": 1, "public_key": KYBER_PUBLIC}]),
                "enforce": True,
            },
            {
                "payload": _bundle(one_time_kyber_prekeys=[{"key_id": 4, "public_key": "33" * 32}]),
                "enforce": True,
            },
            {
                "payload": _bundle(
                    one_time_kyber_prekeys=[
                        {"key_id": index, "public_key": KYBER_PUBLIC} for index in range(MAX_ONE_TIME_BATCH + 1)
                    ]
                ),
                "enforce": True,
            },
        ],
    ),
    ParityFunction(
        name="bundle_response",
        python=_bundle_response_case,
        cases=[
            {"user_id": 7, "stored": STORED_FULL},
            {"user_id": 1, "stored": STORED_BARE},
        ],
    ),
    ParityFunction(
        name="bundle_list",
        python=_bundle_list_case,
        cases=[
            {"user_id": 7, "stored": [STORED_FULL, STORED_BARE]},
            {"user_id": 2, "stored": []},
        ],
    ),
    ParityFunction(
        name="claim_response",
        python=_claim_case,
        cases=[
            {"one_time": "66" * 32, "one_time_id": 5, "one_time_kyber": None, "one_time_kyber_id": None},
            {"one_time": None, "one_time_id": None, "one_time_kyber": KYBER_PUBLIC, "one_time_kyber_id": 9},
            {"one_time": "66" * 32, "one_time_id": 0, "one_time_kyber": KYBER_PUBLIC, "one_time_kyber_id": 0},
            {"one_time": None, "one_time_id": None, "one_time_kyber": None, "one_time_kyber_id": None},
        ],
    ),
    ParityFunction(
        name="status",
        python=_status_case,
        cases=[
            {"published": False, "signed_prekey_id": None, "available": 0, "supports_v2": None},
            {"published": True, "signed_prekey_id": 3, "available": 0, "supports_v2": True},
            {"published": True, "signed_prekey_id": 3, "available": LOW_ONE_TIME_THRESHOLD - 1, "supports_v2": False},
            {"published": True, "signed_prekey_id": 3, "available": LOW_ONE_TIME_THRESHOLD, "supports_v2": None},
            {"published": True, "signed_prekey_id": 0, "available": 100, "supports_v2": True},
        ],
    ),
    ParityFunction(
        name="client_device_id",
        python=_device_id_case,
        cases=[
            {"header": CLIENT_DEVICE_ID},
            {"header": None},
            {"header": ""},
            {"header": "0123456789ABCDEF0123456789abcdef"},
            {"header": "0123456789abcdef0123456789abcde"},
            {"header": "0123456789abcdef0123456789abcdef0"},
            {"header": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
            {"header": "ф" * 16},
        ],
    ),
]

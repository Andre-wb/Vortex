"""
app/chats/_chat_router.py — Shared router instance and chat utility helpers.

All chat sub-modules import the router from here so registrations land
on the same APIRouter that main.py includes.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter

from app.chats.messages.envelope_backend import (
    message_client_stamp,
    message_enc_version,
    message_wire_stamp,
)

router = APIRouter(tags=["chat"])

EPOCH = datetime(1970, 1, 1)

DANGEROUS_EXTS = frozenset(
    {
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".phtml",
        ".asp",
        ".aspx",
        ".ascx",
        ".ashx",
        ".jsp",
        ".jspx",
        ".jws",
        ".cgi",
        ".pl",
        ".py",
        ".rb",
        ".sh",
        ".bash",
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
    }
)


def epoch_micros(dt: datetime) -> int:
    """Микросекунды с эпохи для наивного UTC-времени (aware приводится к UTC)."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    delta = dt - EPOCH
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def from_epoch_micros(microseconds: int) -> datetime:
    """Наивное UTC-время из микросекунд с эпохи."""
    return EPOCH + timedelta(microseconds=microseconds)


def utc_iso(dt: datetime | None) -> str | None:
    """Serialize datetime to ISO 8601 with Z suffix (UTC)."""
    if dt is None:
        return None
    return message_wire_stamp(epoch_micros(dt))


def parse_client_ts(raw: str | None) -> datetime | None:
    """Parse client-provided ISO timestamp; accept only if within ±5 min of server UTC."""
    if not raw or not isinstance(raw, str):
        return None
    now = epoch_micros(datetime.now(timezone.utc))
    stamp = message_client_stamp(raw, now)
    return None if stamp is None else from_epoch_micros(stamp)


def parse_enc_v(data: dict) -> int | None:
    """Validate the envelope encryption-version field.

    Returns the version as int when it is a sane small integer, otherwise None
    (treated as a pre-versioning envelope). Unknown-but-valid versions are kept
    as-is: the server stores and relays ciphertext opaquely and must not reject
    formats it does not understand.
    """
    try:
        payload = json.dumps({"enc_v": data.get("enc_v")})
    except (TypeError, ValueError):
        return None
    return message_enc_version(payload)


def check_double_extension(filename: str) -> bool:
    """Return True if filename has a dangerous intermediate extension (e.g. file.php.jpg)."""
    name = Path(filename).name
    parts = name.split(".")
    if len(parts) <= 2:
        return False
    intermediate = {"." + p.lower() for p in parts[1:-1]}
    return bool(intermediate & DANGEROUS_EXTS)

"""
app/chats/_chat_router.py — Shared router instance and chat utility helpers.

All chat sub-modules import the router from here so registrations land
on the same APIRouter that main.py includes.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter

router = APIRouter(tags=["chat"])

DANGEROUS_EXTS = frozenset({
    '.php', '.php3', '.php4', '.php5', '.phtml',
    '.asp', '.aspx', '.ascx', '.ashx',
    '.jsp', '.jspx', '.jws',
    '.cgi', '.pl', '.py', '.rb', '.sh', '.bash',
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs',
})


def utc_iso(dt: datetime | None) -> str | None:
    """Serialize datetime to ISO 8601 with Z suffix (UTC)."""
    if dt is None:
        return None
    # All DB datetimes should be naive UTC (via datetime.utcnow defaults).
    # If somehow aware, convert to UTC first.
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_client_ts(raw: str | None) -> datetime | None:
    """Parse client-provided ISO timestamp; accept only if within ±5 min of server UTC."""
    if not raw or not isinstance(raw, str):
        return None
    try:
        ts = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        ts_naive = ts.replace(tzinfo=None)
        diff = abs((datetime.now(timezone.utc).replace(tzinfo=None) - ts_naive).total_seconds())
        return ts_naive if diff <= 300 else None
    except (ValueError, TypeError):
        return None


def parse_enc_v(data: dict) -> int | None:
    """Validate the envelope encryption-version field.

    Returns the version as int when it is a sane small integer, otherwise None
    (treated as a pre-versioning envelope). Unknown-but-valid versions are kept
    as-is: the server stores and relays ciphertext opaquely and must not reject
    formats it does not understand.
    """
    v = data.get("enc_v")
    if isinstance(v, bool):  # bool is an int subclass — never a version
        return None
    if isinstance(v, int) and 0 <= v <= 255:
        return v
    return None


def check_double_extension(filename: str) -> bool:
    """Return True if filename has a dangerous intermediate extension (e.g. file.php.jpg)."""
    name  = Path(filename).name
    parts = name.split('.')
    if len(parts) <= 2:
        return False
    intermediate = {'.' + p.lower() for p in parts[1:-1]}
    return bool(intermediate & DANGEROUS_EXTS)

"""Handoff tokens for transferring a user session between Vortex nodes.

A handoff token is a signed envelope produced by the *source* node. The target
node accepts it only after verifying the signature against the source node's
published Ed25519 key.

Envelope shape:
    {
      "payload": {
        "v": 1,
        "typ": "handoff",
        "user_pubkey": "<hex>",       # client-side identity (X25519 pubkey)
        "username": "alice",          # best-effort display name (non-authoritative)
        "src_node_pubkey": "<hex>",   # ed25519 pubkey of source node
        "cursor": {                   # state to carry over
          "last_bmp_ts": 1700000000,
          "rooms": [room_id, ...]
        },
        "iat": 1700000000,
        "exp": 1700000300,            # 5 min
        "jti": "<hex>"
      },
      "signature": "<hex>"            # Ed25519 over canonical(payload)
    }

Target-side verification:
    1. Check exp / iat skew.
    2. Check jti not reused (anti-replay).
    3. Look up src_node_pubkey — either via cached controller registry, or
       by calling controller_client.fetch_random_peers / lookup.
    4. Verify Ed25519 signature with src_node_pubkey.
"""
from __future__ import annotations

import json
import secrets
import time
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.peer.controller_client import NodeSigningKey


HANDOFF_TTL_SEC = 300          # 5 min window to consume the token
HANDOFF_SKEW_SEC = 60           # accept small clock drift


# ── Canonical JSON (must match the rest of the codebase) ──────────────────


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ── Issue ─────────────────────────────────────────────────────────────────


def issue_handoff_token(
    signing_key: NodeSigningKey,
    user_pubkey: str,
    username: str,
    rooms: list[int],
    last_bmp_ts: float = 0.0,
) -> dict:
    """Build and sign a handoff token.

    ``signing_key`` is the source node's Ed25519 identity (same one used to
    register with the controller).
    """
    now = int(time.time())
    payload = {
        "v": 1,
        "typ": "handoff",
        "user_pubkey": user_pubkey,
        "username": username,
        "src_node_pubkey": signing_key.pubkey_hex(),
        "cursor": {
            "last_bmp_ts": float(last_bmp_ts),
            "rooms": sorted(int(r) for r in rooms),
        },
        "iat": now,
        "exp": now + HANDOFF_TTL_SEC,
        "jti": secrets.token_hex(16),
    }
    return {
        "payload": payload,
        "signature": signing_key.sign(payload),
    }


# ── Verify ────────────────────────────────────────────────────────────────


class HandoffError(Exception):
    """Raised when a handoff token is malformed, expired, or unverifiable."""


# Simple in-memory jti cache for anti-replay. Keeps each jti for 2x TTL so
# both sides of a clock skew are covered.
_JTI_SEEN: dict[str, float] = {}
_JTI_TTL_SEC = HANDOFF_TTL_SEC * 2


def _gc_jti(now: float) -> None:
    cutoff = now - _JTI_TTL_SEC
    for k, ts in list(_JTI_SEEN.items()):
        if ts < cutoff:
            del _JTI_SEEN[k]


def verify_handoff_token(
    envelope: dict,
    source_pubkey_resolver,
) -> dict:
    """Validate a handoff token; return the ``payload`` on success.

    ``source_pubkey_resolver`` is a callable: ``fn(pubkey_hex) -> bool`` that
    tells us whether we trust the given source-node pubkey (e.g. it's listed
    in the controller registry, or it matches a locally configured peer).
    """
    try:
        payload = envelope["payload"]
        sig_hex = envelope["signature"]
    except (KeyError, TypeError):
        raise HandoffError("malformed envelope")

    if payload.get("typ") != "handoff" or payload.get("v") != 1:
        raise HandoffError("unsupported token type or version")

    now = int(time.time())
    exp = int(payload.get("exp", 0))
    iat = int(payload.get("iat", 0))
    if exp <= now - HANDOFF_SKEW_SEC:
        raise HandoffError("token expired")
    if iat > now + HANDOFF_SKEW_SEC:
        raise HandoffError("token issued in the future")

    jti = payload.get("jti")
    if not jti:
        raise HandoffError("missing jti")
    _gc_jti(now)
    if jti in _JTI_SEEN:
        raise HandoffError("replay detected")

    src_pubkey = payload.get("src_node_pubkey", "")
    if not src_pubkey:
        raise HandoffError("missing src_node_pubkey")
    if not source_pubkey_resolver(src_pubkey):
        raise HandoffError("unknown source node")

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(src_pubkey))
        pub.verify(bytes.fromhex(sig_hex), _canonical(payload))
    except (ValueError, InvalidSignature) as e:
        raise HandoffError(f"signature invalid: {e}")

    # Accept the jti (consume) only after everything else passed.
    _JTI_SEEN[jti] = now
    return payload


def _reset_replay_cache_for_tests() -> None:
    """Test helper — clear the jti cache between test cases."""
    _JTI_SEEN.clear()

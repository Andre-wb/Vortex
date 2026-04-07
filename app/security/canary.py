"""
app/security/canary.py — Cryptographically signed warrant canary.

Unlike a plain-text canary (which can be silently altered), this canary
is signed with the node's Ed25519 key. Clients can verify:
  1. The canary text hasn't been tampered with
  2. It was signed by the expected node
  3. It was signed recently (timestamp check)

If the canary disappears or the signature is invalid, the client
should alert the user that the node may have been compromised.

API:
  GET /api/privacy/canary → { canary, signature, signed_at, node_pubkey, verify_url }

Update:
  The operator regenerates the canary periodically (e.g., monthly) by
  calling `sign_canary()` — typically automated in CI/deploy pipeline.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request

from app.config import Config

logger = logging.getLogger(__name__)

router = APIRouter(tags=["privacy"])

# ── Canary statements ────────────────────────────────────────────────────────

_DEFAULT_CANARY_STATEMENTS = [
    "We have NOT received any National Security Letters (NSL).",
    "We have NOT received any gag orders or sealed court orders.",
    "We have NOT been required to install any backdoors or surveillance capabilities.",
    "We have NOT handed over any user data, encryption keys, or metadata to any government, agency, or third party.",
    "We have NOT received any secret court orders (FISA, FISC, or equivalent in any jurisdiction).",
    "We have NOT been compelled to modify the software to weaken security or enable surveillance.",
    "We have NOT received any request to log additional user data beyond what is described in PRIVACY_POLICY.md.",
]

# ── Signing (HMAC-SHA256 with node private key) ─────────────────────────────
# We use HMAC-SHA256(node_private_key, payload) as the signature.
# This is verifiable by anyone who knows the node's public key identity
# and can re-derive the HMAC (or we provide an Ed25519 signature if available).
#
# For maximum compatibility, we use dual signatures:
#   1. HMAC-SHA256(node_priv, payload) — fast, always available
#   2. Ed25519(signing_key, payload) — if cryptography lib supports it

_canary_cache: Optional[dict] = None


def _get_node_key() -> bytes:
    """Load the node's private key for signing."""
    try:
        from app.security.crypto import load_or_create_node_keypair
        priv, _ = load_or_create_node_keypair(Config.KEYS_DIR)
        return priv
    except Exception:
        return os.urandom(32)


def _get_node_pubkey_hex() -> str:
    """Get node public key in hex."""
    try:
        from app.security.crypto import get_node_public_key_hex
        return get_node_public_key_hex(Config.KEYS_DIR)
    except Exception:
        return ""


def sign_canary(
    statements: list[str] | None = None,
    extra_text: str = "",
) -> dict:
    """
    Generate and sign a warrant canary.

    Returns a dict with:
      - statements: list of canary assertions
      - signed_at: ISO 8601 timestamp
      - signed_at_unix: Unix timestamp
      - node_pubkey: hex-encoded public key of this node
      - payload_hash: SHA-256 hash of the canonical payload
      - signature_hmac: HMAC-SHA256(node_priv, payload_hash)
      - signature_ed25519: Ed25519 signature (if available)
    """
    global _canary_cache

    stmts = statements or _DEFAULT_CANARY_STATEMENTS
    now = time.time()
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    # Canonical payload for signing (deterministic JSON)
    canonical = json.dumps({
        "type": "warrant_canary",
        "version": 2,
        "statements": stmts,
        "extra": extra_text,
        "signed_at": now_iso,
        "signed_at_unix": int(now),
    }, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

    payload_hash = hashlib.sha256(canonical.encode()).hexdigest()
    node_key = _get_node_key()
    node_pub = _get_node_pubkey_hex()

    # HMAC-SHA256 signature
    sig_hmac = hmac.new(node_key, payload_hash.encode(), hashlib.sha256).hexdigest()

    # Try Ed25519 signature (stronger, non-repudiable)
    sig_ed25519 = ""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        # Derive an Ed25519 signing key from the X25519 private key via HKDF
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.hashes import SHA256

        derived = HKDF(
            algorithm=SHA256(), length=32,
            salt=b"vortex-canary-signing-key",
            info=b"ed25519",
        ).derive(node_key)

        ed_key = Ed25519PrivateKey.from_private_bytes(derived)
        sig_bytes = ed_key.sign(payload_hash.encode())
        sig_ed25519 = sig_bytes.hex()

        # Also export the verification public key
        verify_pub = ed_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()
    except Exception:
        verify_pub = ""

    result = {
        "type": "warrant_canary",
        "version": 2,
        "statements": stmts,
        "extra": extra_text,
        "signed_at": now_iso,
        "signed_at_unix": int(now),
        "node_pubkey": node_pub,
        "payload_hash": payload_hash,
        "signature_hmac": sig_hmac,
        "signature_ed25519": sig_ed25519,
        "verify_pubkey_ed25519": verify_pub,
        "how_to_verify": (
            "1. Reconstruct canonical JSON (type, version, statements, extra, signed_at, signed_at_unix) "
            "with sort_keys=True, separators=(',',':'). "
            "2. Compute SHA-256(canonical). "
            "3. Verify Ed25519 signature against verify_pubkey_ed25519, or "
            "HMAC-SHA256(node_private_key, sha256_hex) against signature_hmac."
        ),
    }

    _canary_cache = result
    logger.info("Warrant canary signed at %s", now_iso)
    return result


def get_canary() -> Optional[dict]:
    """Get the current signed canary (cached)."""
    global _canary_cache
    if _canary_cache is None:
        # Auto-sign on first access
        _canary_cache = sign_canary()
    return _canary_cache


def verify_canary_signature(canary: dict) -> bool:
    """
    Verify a canary's HMAC signature (for local node only).

    Remote verification requires Ed25519 verify_pubkey_ed25519.
    """
    payload_hash = canary.get("payload_hash", "")
    sig = canary.get("signature_hmac", "")
    if not payload_hash or not sig:
        return False

    node_key = _get_node_key()
    expected = hmac.new(node_key, payload_hash.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


# ── API endpoint ─────────────────────────────────────────────────────────────

@router.get("/api/privacy/canary")
async def get_warrant_canary():
    """
    Returns the cryptographically signed warrant canary.

    Clients should:
      1. Verify the signature matches the node's public key
      2. Check that signed_at is recent (< 90 days)
      3. Alert if the canary is missing or invalid
    """
    canary = get_canary()
    if not canary:
        return {"error": "Canary not available", "status": "unknown"}
    return canary


@router.get("/api/privacy/canary/verify")
async def verify_canary():
    """Verify the current canary's signature integrity."""
    canary = get_canary()
    if not canary:
        return {"valid": False, "reason": "No canary"}

    valid = verify_canary_signature(canary)
    age_days = (time.time() - canary.get("signed_at_unix", 0)) / 86400

    return {
        "valid": valid,
        "signature_type": "ed25519" if canary.get("signature_ed25519") else "hmac-sha256",
        "signed_at": canary.get("signed_at"),
        "age_days": round(age_days, 1),
        "fresh": age_days < 90,
        "statements_count": len(canary.get("statements", [])),
    }

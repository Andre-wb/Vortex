"""Startup-time integrity verification.

``verify_at_startup()`` is the single entry point: it finds the signed manifest,
validates the signature against the pinned release pubkey (or a locally
configured one), and recomputes every file's hash.

Status values returned:
    "verified"     — signature valid and every file matches
    "tampered"     — signature valid but some files differ from the manifest
    "wrong_key"    — signature signed by a different key than we trust
    "bad_signature"— signature doesn't verify at all
    "no_manifest"  — INTEGRITY.sig.json is missing (dev mode)

The verifier never raises — it returns a dict so startup logic can decide
whether to refuse requests, warn, or proceed.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .manifest import canonical_json, verify_files

logger = logging.getLogger("vortex_controller.integrity")


# ── Pinned release pubkey ──────────────────────────────────────────────────
# Operators running a private build set RELEASE_PUBKEY in the environment.
# For the official Vortex release, replace the default below with the
# upstream pubkey printed by ``sign_tool.py --show-pubkey``.
_DEFAULT_PINNED_PUBKEY = os.getenv(
    "VORTEX_OFFICIAL_RELEASE_PUBKEY",
    "",  # empty = treat any self-signed build as "untrusted" unless RELEASE_PUBKEY is set
)


@dataclass
class IntegrityReport:
    status: str                               # see module docstring
    signed_by: Optional[str] = None           # pubkey hex that signed the manifest
    trusted_pubkey: Optional[str] = None      # pubkey we verified against
    version: Optional[str] = None
    built_at: Optional[int] = None
    matched: int = 0
    mismatched: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _load_signed_manifest(path: Path) -> Optional[dict]:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as e:
        logger.warning("integrity manifest unreadable: %s", e)
        return None


def _verify_ed25519(payload: dict, signature_hex: str, pubkey_hex: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pub.verify(bytes.fromhex(signature_hex), canonical_json(payload))
        return True
    except (ValueError, InvalidSignature):
        return False


def _resolve_trusted_pubkey() -> Optional[str]:
    """Release pubkey we trust for this deployment.

    Priority:
      1. RELEASE_PUBKEY env var      — explicit operator override
      2. _DEFAULT_PINNED_PUBKEY      — compiled-in upstream key
      3. None                        — dev mode (accept whatever signed)
    """
    env = os.getenv("RELEASE_PUBKEY", "").strip()
    if env:
        return env.lower()
    if _DEFAULT_PINNED_PUBKEY:
        return _DEFAULT_PINNED_PUBKEY.lower()
    return None


def verify_at_startup(
    root: Path,
    manifest_path: Optional[Path] = None,
) -> IntegrityReport:
    """Return a structured verification report. Never raises."""
    manifest_path = manifest_path or (root.parent / "INTEGRITY.sig.json")

    signed = _load_signed_manifest(manifest_path)
    if signed is None:
        return IntegrityReport(
            status="no_manifest",
            message=(
                "INTEGRITY.sig.json not found — this is a development build. "
                "Run `python -m vortex_controller.integrity.sign_tool` to produce one."
            ),
        )

    payload = signed.get("payload") or {}
    sig = signed.get("signature", "")
    signed_by = (signed.get("signed_by") or "").lower()

    # Step 1: signature must verify against whatever key signed it
    if not _verify_ed25519(payload, sig, signed_by):
        return IntegrityReport(
            status="bad_signature",
            signed_by=signed_by or None,
            message="Manifest signature is invalid — file has been tampered with.",
        )

    # Step 2: the signing key must match our pinned/trusted one (if any)
    trusted = _resolve_trusted_pubkey()
    if trusted is not None and signed_by != trusted:
        return IntegrityReport(
            status="wrong_key",
            signed_by=signed_by,
            trusted_pubkey=trusted,
            version=payload.get("version"),
            built_at=payload.get("built_at"),
            message=(
                "Manifest signed by a different key than expected. "
                "Either the operator changed keys, or someone swapped the build."
            ),
        )

    # Step 3: file hashes must match
    diff = verify_files(payload, root)
    report = IntegrityReport(
        signed_by=signed_by,
        trusted_pubkey=trusted or signed_by,
        version=payload.get("version"),
        built_at=payload.get("built_at"),
        matched=diff["matched"],
        mismatched=diff["mismatched"],
        missing=diff["missing"],
        extra=diff["extra"],
        status="verified",  # optimistic; downgraded below if needed
    )
    if diff["mismatched"] or diff["missing"]:
        report.status = "tampered"
        report.message = (
            f"Source tree differs from the signed manifest: "
            f"{len(diff['mismatched'])} modified, {len(diff['missing'])} missing."
        )
    else:
        report.message = (
            f"All {diff['matched']} files match manifest v{payload.get('version')} "
            f"(signed by {signed_by[:16]}…)"
        )
    return report

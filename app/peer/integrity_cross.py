"""Cross-verify a controller's code hash against the Solana on-chain seal.

Phase 7C. The controller reports ``signed_by`` + ``version`` in its
``/v1/integrity`` response — that's enough to catch a tampered manifest,
but not enough to catch "operator re-signed a modified manifest with
their own key and updated SNS". The on-chain seal closes that gap:
every seal/checkin is a publicly-visible historical record that can't
be silently revised.

Flow for a paranoid client connecting to a controller:

    1. GET /v1/integrity                    → status, signed_by, version
    2. GET /INTEGRITY.sig.json              → raw signed manifest
    3. sha256(manifest)                     → controller_hash
    4. Fetch Solana peer record             → on_chain.code_hash
    5. If sealed AND on_chain.code_hash == controller_hash → TRUST
       Otherwise                                         → REFUSE
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Optional

import httpx

from .solana_registry import PeerAccount, SolanaRegistryClient

logger = logging.getLogger(__name__)


async def cross_verify_controller(
    controller_url: str,
    solana_rpc_url: str,
    program_id: str,
    node_pubkey_hex: str,
    timeout: float = 10.0,
) -> dict:
    """Confirm the running controller matches what's sealed on Solana.

    Returns a dict describing the check outcome:

        {
            "ok":                 bool,   # all checks passed
            "controller_status":  str|None,
            "controller_hash":    str|None,   # hex sha256 of manifest
            "onchain_hash":       str|None,   # hex sha256 stored on Solana
            "sealed":             bool,
            "last_checkin_age":   int|None,   # seconds
            "reason":             str,
        }
    """
    result = {
        "ok": False,
        "controller_status": None,
        "controller_hash": None,
        "onchain_hash": None,
        "sealed": False,
        "last_checkin_age": None,
        "reason": "",
    }

    # 1. Controller integrity
    try:
        async with httpx.AsyncClient(timeout=timeout) as http:
            r = await http.get(f"{controller_url.rstrip('/')}/v1/integrity")
            r.raise_for_status()
            integrity = r.json()
    except Exception as e:
        result["reason"] = f"controller unreachable: {e}"
        return result

    result["controller_status"] = integrity.get("status")
    if integrity.get("status") != "verified":
        result["reason"] = f"controller status = {integrity.get('status')}"
        return result

    # 2. Manifest fetch → hash
    controller_hash = await _fetch_and_hash_manifest(controller_url, timeout)
    if controller_hash is None:
        result["reason"] = "manifest not available for hashing"
        return result
    result["controller_hash"] = controller_hash

    # 3. On-chain seal lookup
    peer = await _find_peer_on_chain(solana_rpc_url, program_id, node_pubkey_hex)
    if peer is None:
        result["reason"] = "node not found in on-chain registry"
        return result

    result["sealed"] = peer.is_sealed
    result["onchain_hash"] = peer.code_hash_hex if peer.is_sealed else None
    if peer.last_checkin:
        import time
        result["last_checkin_age"] = int(time.time()) - peer.last_checkin

    if not peer.is_sealed:
        result["reason"] = "node has not called seal() yet"
        return result

    if peer.code_hash_hex.lower() != controller_hash.lower():
        result["reason"] = (
            f"hash mismatch: on-chain={peer.code_hash_hex[:16]}… "
            f"controller={controller_hash[:16]}…"
        )
        return result

    result["ok"] = True
    result["reason"] = "on-chain seal matches controller manifest"
    return result


async def _find_peer_on_chain(
    solana_rpc_url: str,
    program_id: str,
    node_pubkey_hex: str,
) -> Optional[PeerAccount]:
    """Linear scan of program accounts for a peer matching ``node_pubkey_hex``.

    Ed25519-based PDA derivation is out of scope for this pure-Python client;
    the scan is cheap because the registry is small (hundreds of peers at most).
    """
    client = SolanaRegistryClient(rpc_url=solana_rpc_url, program_id=program_id)
    try:
        peers = await client.fetch_peers()
    except Exception as e:
        logger.debug("on-chain fetch failed: %s", e)
        return None
    target = node_pubkey_hex.lower()
    for p in peers:
        if p.node_pubkey_hex.lower() == target:
            return p
    return None


async def _fetch_and_hash_manifest(
    controller_url: str,
    timeout: float,
) -> Optional[str]:
    """SHA-256 of the controller's signed manifest bundle."""
    # Direct fetch of the signed envelope if exposed
    try:
        async with httpx.AsyncClient(timeout=timeout) as http:
            r = await http.get(f"{controller_url.rstrip('/')}/INTEGRITY.sig.json")
            if r.status_code == 200:
                return hashlib.sha256(r.content).hexdigest()
    except Exception as e:
        logger.debug("manifest direct fetch failed: %s", e)

    # Fallback: reconstruct a canonical fingerprint from /v1/integrity.
    # This is weaker (doesn't cover the signature itself) but still catches
    # release-key changes or version bumps without a matching on-chain checkin.
    try:
        async with httpx.AsyncClient(timeout=timeout) as http:
            r = await http.get(f"{controller_url.rstrip('/')}/v1/integrity")
            if r.status_code != 200:
                return None
            j = r.json()
        canonical = json.dumps(
            {
                "signed_by": j.get("signed_by"),
                "version":   j.get("version"),
                "built_at":  j.get("built_at"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(canonical).hexdigest()
    except Exception:
        return None

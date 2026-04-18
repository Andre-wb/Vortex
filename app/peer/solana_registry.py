"""Read-only client for the on-chain Vortex peer registry (Phase 5).

Talks to any Solana JSON-RPC endpoint (Devnet, Mainnet, local validator, or a
public RPC like Helius/Ankr) via plain HTTP — no ``solana-py`` dependency.
Writes (register/heartbeat) are not implemented here: node operators run the
Anchor TypeScript client or a signed-tx tool. For clients the read path is
what matters — they just need to discover peers.

Quick start::

    client = SolanaRegistryClient(
        rpc_url="https://api.devnet.solana.com",
        program_id="Vor1exReg11111111111111111111111111111111",
    )
    peers = await client.fetch_peers(online_window_sec=300)
    for p in peers:
        print(p.node_pubkey_hex, p.endpoints)

The on-chain account layout is Borsh-encoded by Anchor::

    [8:  discriminator (sha256("account:Peer")[:8])]
    [32: owner pubkey]
    [32: node_pubkey (ed25519)]
    [4:  endpoints len (u32 LE)]
    [ for each: 4 bytes string len + utf-8 body ]
    [4:  metadata len + utf-8]
    [8:  registered_at (i64 LE)]
    [8:  last_heartbeat (i64 LE)]
    [1:  bump]
"""
from __future__ import annotations

import base64
import hashlib
import logging
import struct
import time
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Anchor derives an 8-byte account discriminator from the account struct name.
_ACCOUNT_DISCRIMINATOR = hashlib.sha256(b"account:Peer").digest()[:8]


# ══════════════════════════════════════════════════════════════════════════
# Public data type
# ══════════════════════════════════════════════════════════════════════════


@dataclass
class PeerAccount:
    """One on-chain peer record (Phase 5 + 7 fields)."""
    pda: str                       # the PDA address as a base58 string
    owner: bytes                   # 32-byte owner pubkey
    node_pubkey: bytes             # 32-byte node ed25519 pubkey
    endpoints: list[str]
    metadata: str                  # raw JSON-ish string as written by the operator
    registered_at: int
    last_heartbeat: int
    bump: int
    # Phase 7 fields
    code_hash: bytes = b"\x00" * 32
    is_sealed: bool = False
    first_sealed_at: int = 0
    last_checkin: int = 0

    @property
    def node_pubkey_hex(self) -> str:
        return self.node_pubkey.hex()

    @property
    def code_hash_hex(self) -> str:
        return self.code_hash.hex()

    def is_online(self, window_sec: int = 300, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        return (now - self.last_heartbeat) <= window_sec

    def weight(self, now: Optional[float] = None) -> float:
        """Phase 7 trust decay: newer check-ins → more weight.

        Returns 1.0 for freshly-checked-in sealed nodes, linearly decaying
        down to 0.0 after ~180 days of silence. Un-sealed nodes get at
        most 0.5 (they haven't committed to a code hash yet).
        """
        now = now if now is not None else time.time()
        ts = max(self.last_checkin, self.last_heartbeat)
        if ts <= 0:
            return 0.0
        days_since = max(0.0, (now - ts) / 86400)
        if days_since < 7:
            base = 1.0
        elif days_since < 30:
            base = 0.8
        elif days_since < 90:
            base = 0.5
        elif days_since < 180:
            base = 0.2
        else:
            base = 0.0
        return base if self.is_sealed else min(base, 0.5)

    def to_controller_peer(self) -> dict:
        """Shape matches the HTTP controller's peer view (see Phase 1)."""
        parsed_meta: dict = {}
        try:
            import json
            if self.metadata:
                parsed_meta = json.loads(self.metadata)
                if not isinstance(parsed_meta, dict):
                    parsed_meta = {"raw": self.metadata}
        except (ValueError, TypeError):
            parsed_meta = {"raw": self.metadata}
        return {
            "pubkey": self.node_pubkey_hex,
            "endpoints": list(self.endpoints),
            "metadata": parsed_meta,
            "last_seen": int(self.last_heartbeat),
            # Phase 7 extras — clients use these for cross-verification + weighting
            "code_hash": self.code_hash_hex if self.is_sealed else None,
            "sealed": self.is_sealed,
            "last_checkin": int(self.last_checkin),
            "weight": round(self.weight(), 3),
        }


# ══════════════════════════════════════════════════════════════════════════
# Borsh parser — just enough for the Peer account shape
# ══════════════════════════════════════════════════════════════════════════


class _Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError(f"truncated: need {n} at {self.pos}, have {len(self.data) - self.pos}")
        b = self.data[self.pos : self.pos + n]
        self.pos += n
        return b

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.take(8))[0]

    def u8(self) -> int:
        return self.take(1)[0]

    def string(self) -> str:
        n = self.u32()
        return self.take(n).decode("utf-8")


def parse_peer_account(data: bytes, pda: str = "") -> PeerAccount:
    """Deserialize a Borsh-encoded Peer account (Phase 5 + 7 layout).

    The layout matches ``solana_program/programs/vortex_registry/src/lib.rs``
    exactly. Older accounts signed with the Phase 5 schema still parse fine —
    they just have zeroed ``code_hash`` / ``is_sealed`` fields (we detect the
    truncated length and fill defaults).
    """
    if len(data) < 8:
        raise ValueError("account data too short")
    if data[:8] != _ACCOUNT_DISCRIMINATOR:
        raise ValueError("discriminator mismatch (not a Peer account)")

    r = _Reader(data[8:])  # skip discriminator
    owner = r.take(32)
    node_pubkey = r.take(32)
    ep_count = r.u32()
    if ep_count > 32:
        raise ValueError(f"too many endpoints: {ep_count}")
    endpoints = [r.string() for _ in range(ep_count)]
    metadata = r.string()
    registered_at = r.i64()
    last_heartbeat = r.i64()
    bump = r.u8()

    # Phase 7 fields — may be absent on legacy accounts.
    code_hash = b"\x00" * 32
    is_sealed = False
    first_sealed_at = 0
    last_checkin = 0
    if r.pos + 32 + 1 + 8 + 8 <= len(r.data):
        code_hash = r.take(32)
        is_sealed = r.u8() != 0
        first_sealed_at = r.i64()
        last_checkin = r.i64()

    return PeerAccount(
        pda=pda,
        owner=owner,
        node_pubkey=node_pubkey,
        endpoints=endpoints,
        metadata=metadata,
        registered_at=registered_at,
        last_heartbeat=last_heartbeat,
        bump=bump,
        code_hash=code_hash,
        is_sealed=is_sealed,
        first_sealed_at=first_sealed_at,
        last_checkin=last_checkin,
    )


# ══════════════════════════════════════════════════════════════════════════
# RPC client
# ══════════════════════════════════════════════════════════════════════════


class SolanaRpcError(RuntimeError):
    pass


class SolanaRegistryClient:
    """Minimal Solana JSON-RPC client for reading Vortex peer records."""

    def __init__(
        self,
        rpc_url: str,
        program_id: str,
        timeout: float = 10.0,
    ):
        self.rpc_url = rpc_url.rstrip("/")
        self.program_id = program_id
        self.timeout = timeout

    async def _rpc(self, method: str, params: list) -> dict:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as http:
            r = await http.post(self.rpc_url, json=payload)
            r.raise_for_status()
            body = r.json()
        if "error" in body:
            raise SolanaRpcError(str(body["error"]))
        return body.get("result", {})

    async def fetch_peers(
        self,
        online_window_sec: Optional[int] = None,
        now: Optional[float] = None,
    ) -> list[PeerAccount]:
        """Fetch every Peer account owned by the program.

        If ``online_window_sec`` is given, only peers whose ``last_heartbeat``
        falls within that window are returned.
        """
        result = await self._rpc("getProgramAccounts", [
            self.program_id,
            {
                "encoding": "base64",
                "filters": [
                    # Filter server-side on the discriminator so the RPC doesn't
                    # send us other account types. Borsh-encoded as 8 raw bytes
                    # starting at offset 0.
                    {
                        "memcmp": {
                            "offset": 0,
                            "bytes": _b58encode(_ACCOUNT_DISCRIMINATOR),
                        }
                    }
                ],
            },
        ])

        peers: list[PeerAccount] = []
        for item in result or []:
            pda = item.get("pubkey", "")
            account = item.get("account") or {}
            data_entry = account.get("data")
            if not data_entry:
                continue
            raw_b64 = data_entry[0] if isinstance(data_entry, list) else data_entry
            try:
                raw = base64.b64decode(raw_b64)
                p = parse_peer_account(raw, pda=pda)
            except Exception as e:
                logger.debug("skip invalid peer %s: %s", pda, e)
                continue
            if online_window_sec is not None and not p.is_online(online_window_sec, now=now):
                continue
            peers.append(p)
        return peers


# ══════════════════════════════════════════════════════════════════════════
# Base58 (needed for memcmp filter encoding; small impl, no deps)
# ══════════════════════════════════════════════════════════════════════════

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHABET[r])
    # Preserve leading zero bytes as '1's (Bitcoin/Solana convention)
    for b in data:
        if b == 0:
            out.append(_B58_ALPHABET[0])
        else:
            break
    return bytes(reversed(out)).decode("ascii")

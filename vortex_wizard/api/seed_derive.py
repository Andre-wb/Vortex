"""BIP39 seed → Ed25519 identity + Solana wallet derivation.

A single 24-word BIP39 mnemonic is the master secret for an operator.
From it we derive two independent Ed25519 keypairs using SLIP-0010:

  * m/44'/9000'/0'/0'   — node identity (signs heartbeats, authenticates
                          the node to the controller). Stored at
                          ``keys/ed25519_signing.bin`` as raw 32 bytes.
  * m/44'/501'/0'/0'    — Solana wallet (receives rewards, pays register
                          fee on-chain). Standard Solana derivation path.

Paths use all-hardened indices because Ed25519 SLIP-0010 does not define
non-hardened child derivation. A compromise of the node key does not
reveal the wallet key and vice versa — they are independent children of
the master seed.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass


# SLIP-0010 Ed25519 magic string — specified by the standard.
_ED25519_MASTER_KEY = b"ed25519 seed"

# All indices in Ed25519 SLIP-0010 paths must be hardened (>= 2**31).
_HARDENED = 0x80000000

# Path components (see module docstring).
_NODE_PATH = (44, 9000, 0, 0)
_SOLANA_PATH = (44, 501, 0, 0)


def generate_mnemonic() -> str:
    """Return a fresh 24-word BIP39 English mnemonic (256 bits entropy)."""
    from mnemonic import Mnemonic
    return Mnemonic("english").generate(256)


def validate_mnemonic(phrase: str) -> bool:
    from mnemonic import Mnemonic
    return Mnemonic("english").check(normalize_mnemonic(phrase))


def normalize_mnemonic(phrase: str) -> str:
    return " ".join((phrase or "").lower().strip().split())


def mnemonic_to_seed(phrase: str, passphrase: str = "") -> bytes:
    """BIP39 mnemonic → 64-byte seed via PBKDF2-HMAC-SHA512."""
    from mnemonic import Mnemonic
    return Mnemonic.to_seed(normalize_mnemonic(phrase), passphrase=passphrase)


def _slip10_master(seed: bytes) -> tuple[bytes, bytes]:
    mac = hmac.new(_ED25519_MASTER_KEY, seed, hashlib.sha512).digest()
    return mac[:32], mac[32:]


def _slip10_child(key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    if index < _HARDENED:
        raise ValueError("Ed25519 SLIP-0010 requires hardened derivation")
    data = b"\x00" + key + struct.pack(">I", index)
    mac = hmac.new(chain_code, data, hashlib.sha512).digest()
    return mac[:32], mac[32:]


def _derive_path(seed: bytes, path: tuple[int, ...]) -> bytes:
    key, chain = _slip10_master(seed)
    for component in path:
        key, chain = _slip10_child(key, chain, component | _HARDENED)
    return key


def _ed25519_pubkey(priv_raw: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


@dataclass
class DerivedIdentity:
    node_priv_raw: bytes   # 32 bytes — write to keys/ed25519_signing.bin
    node_pubkey_hex: str   # 64 hex chars
    wallet_priv_raw: bytes # 32 bytes — kept in-memory only, never written
    wallet_pubkey_base58: str


def derive_identity(phrase: str, passphrase: str = "") -> DerivedIdentity:
    """Derive both keypairs from a BIP39 mnemonic."""
    import base58

    seed = mnemonic_to_seed(phrase, passphrase=passphrase)

    node_priv = _derive_path(seed, _NODE_PATH)
    node_pub = _ed25519_pubkey(node_priv)

    wallet_priv = _derive_path(seed, _SOLANA_PATH)
    wallet_pub = _ed25519_pubkey(wallet_priv)

    return DerivedIdentity(
        node_priv_raw=node_priv,
        node_pubkey_hex=node_pub.hex(),
        wallet_priv_raw=wallet_priv,
        wallet_pubkey_base58=base58.b58encode(wallet_pub).decode("ascii"),
    )

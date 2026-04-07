"""
app/security/seed_phrase.py — BIP39 24-word mnemonic for anonymous registration.

When a user registers without a phone number, they receive a 24-word
seed phrase (256 bits of entropy). This is the ONLY way to recover
the account — the server stores only an Argon2id hash of the phrase.

Flow:
  1. Register without phone → generate 24-word BIP39 mnemonic
  2. Client shows: "Запишите на бумагу или сохраните в безопасном месте"
  3. Server stores Argon2id(normalize(mnemonic)) — phrase itself NEVER stored
  4. Recovery login: username + seed phrase → verify hash → JWT tokens
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def generate_mnemonic() -> str:
    """Generate a BIP39 24-word mnemonic (256-bit entropy)."""
    from mnemonic import Mnemonic
    return Mnemonic("english").generate(256)


def validate_mnemonic(phrase: str) -> bool:
    """Check if a mnemonic is valid BIP39 English."""
    from mnemonic import Mnemonic
    return Mnemonic("english").check(phrase)


def normalize_mnemonic(phrase: str) -> str:
    """Normalize mnemonic for consistent hashing: lowercase, single spaces."""
    return " ".join(phrase.lower().strip().split())

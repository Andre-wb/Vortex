"""WAFCaptcha — арифметические CAPTCHA (stateless HMAC-signed challenges).

Challenges are self-verifying: the answer + expiry are embedded in the challenge_id
and signed with HMAC-SHA256.  No server-side state is stored, so this works correctly
in multi-instance (horizontal-scaling) deployments — any instance can verify any challenge.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Dict


class WAFCaptcha:
    def __init__(self):
        # Derive HMAC key from app secrets so all instances share the same key.
        # Falls back to a per-process random key when no secret is configured
        # (single-instance, or restarts will invalidate outstanding challenges).
        _raw = os.environ.get("CSRF_SECRET", "") or os.environ.get("JWT_SECRET", "")
        self._secret: bytes = (_raw + "waf-captcha-v1").encode() if _raw else secrets.token_bytes(32)
        self.ttl = 300

    # ── Internal HMAC signing ─────────────────────────────────────────────────

    def _sign(self, payload: str) -> str:
        return hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()

    # ── Public API ─────────────────────────────────────────────────────────────

    def generate_challenge(self, client_ip: str) -> Dict:
        op = secrets.choice(['+', '-', '*'])
        a  = secrets.randbelow(10) + 1
        b  = secrets.randbelow(10) + 1
        if op == '+':
            answer = str(a + b)
        elif op == '-':
            answer = str(a - b)
        else:
            answer = str(a * b)

        expires = int(time.time()) + self.ttl
        # Embed answer + expiry into HMAC signature — no server state needed
        sig = self._sign(f"{answer}:{expires}")
        # Opaque to client: random 8-byte prefix prevents enumeration
        cid = secrets.token_hex(8) + "." + f"{expires}:{sig}"

        return {'challenge_id': cid, 'question': f"What is {a} {op} {b}?", 'expires_in': self.ttl}

    def verify_challenge(self, challenge_id: str, answer: str) -> bool:
        try:
            _, token    = challenge_id.split(".", 1)
            expires_str, sig = token.split(":", 1)
            expires = int(expires_str)
            if time.time() > expires:
                return False
            expected = self._sign(f"{answer.strip()}:{expires}")
            return hmac.compare_digest(sig, expected)
        except (ValueError, AttributeError, IndexError):
            return False

    def cleanup_expired(self):
        pass  # Stateless — nothing to clean up

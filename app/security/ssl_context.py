"""
app/security/ssl_context.py — Shared SSL context for outgoing peer connections.

All server-to-server httpx clients MUST use this instead of verify=False.
The context trusts system CAs + the project's own vortex-ca.crt (self-signed).
"""
from __future__ import annotations

import ssl
from functools import lru_cache
from pathlib import Path

# Path to Vortex self-signed CA certificate
_CA_PATH = Path(__file__).resolve().parents[2] / "certs" / "vortex-ca.crt"


@lru_cache(maxsize=1)
def make_peer_ssl_context() -> ssl.SSLContext:
    """SSL context that trusts system CAs + Vortex self-signed CA.

    Cached: only one SSLContext is ever created per process.
    Certificate verification is ALWAYS enabled.
    """
    ctx = ssl.create_default_context()
    if _CA_PATH.exists():
        ctx.load_verify_locations(str(_CA_PATH))
    return ctx

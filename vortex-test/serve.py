"""Standalone preview server for the vortexx.sol controller website.

Serves the static UI from ``public/`` and mocks every API endpoint the
page calls, so you can see the fully-populated design without needing a
running controller, Solana, Bonfida, IPFS, Tor or any network at all.

Every signed endpoint uses a real Ed25519 keypair generated at startup
and signs responses with the same canonical JSON scheme as the real
controller, so the website's client-side signature verification passes.

Run:

    cd vortex-test
    pip install fastapi uvicorn cryptography
    python serve.py
    # → open http://localhost:7700

No network calls are made, no secrets are saved, no config is required.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"


# ── Generate a throwaway keypair so signatures verify cleanly ─────────────
_PRIV = Ed25519PrivateKey.generate()
_PUB_HEX = _PRIV.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
).hex()


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_envelope(payload: dict) -> dict:
    sig = _PRIV.sign(canonical_json(payload)).hex()
    return {"payload": payload, "signature": sig, "signed_by": _PUB_HEX}


# ── Mock data ─────────────────────────────────────────────────────────────

NOW = int(time.time())
START = NOW

# Entry URLs shown in the "Entry URLs" card
ENTRY_URLS = [
    {"url": "wss://smith-labs-darwin-nicole.trycloudflare.com", "type": "tunnel"},
    {"url": "wss://quiet-fox-harbor-alpha.trycloudflare.com",   "type": "tunnel"},
    {"url": "http://abcdef123ghijk789lmnopqr456stuvwx.onion",   "type": "tor"},
    {"url": "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi", "type": "ipfs"},
    {"url": "wss://controller-mirror.vortex.example",          "type": "direct"},
]

# Mirrors with varied health — surface every badge state
MIRRORS = [
    {"url": "https://mirror-a.vortex.example",          "type": "web",
     "healthy": True,  "latency_ms": 84,  "last_checked": NOW - 20, "error": None},
    {"url": "https://mirror-b.vortex.example",          "type": "web",
     "healthy": False, "latency_ms": None, "last_checked": NOW - 40,
     "error": "ConnectError: connection refused"},
    {"url": "ipfs://bafybei000mirror1pin",              "type": "ipfs",
     "healthy": True,  "latency_ms": 312, "last_checked": NOW - 60, "error": None},
    {"url": "ipfs://bafybei000mirror2stale",            "type": "ipfs",
     "healthy": False, "latency_ms": None, "last_checked": NOW - 180,
     "error": "HTTPStatusError: 504 Gateway Timeout"},
    {"url": "http://m2vortex7example123onion567.onion", "type": "tor",
     "healthy": False, "latency_ms": None, "last_checked": NOW,
     "error": "no tor proxy configured"},
    {"url": "https://another-mirror.vortex.sol.site",   "type": "web",
     "healthy": None,  "latency_ms": None, "last_checked": 0, "error": None},
]

# Peer registry — multiple node types + weight decay demonstration
PEERS = [
    # Fully verified, sealed, fresh — weight 1.0
    {
        "pubkey":   "aa" * 32,
        "endpoints": ["wss://node-eu-west-1.vortex.sol:9000"],
        "metadata": {"name": "node-A (prod)", "region": "eu-west", "version": "1.0.2"},
        "last_seen": NOW - 12,
        "sealed": True, "weight": 1.0,
    },
    # Sealed but missed a check-in — weight 0.8
    {
        "pubkey":   "bb" * 32,
        "endpoints": ["wss://node-us-east-1.vortex.sol:9000",
                      "http://aaanodebb8ej2ka.onion"],
        "metadata": {"name": "node-B", "region": "us-east", "version": "1.0.2"},
        "last_seen": NOW - 3600 * 20,
        "sealed": True, "weight": 0.8,
    },
    # Sealed + Tor + IPFS endpoints
    {
        "pubkey":   "cc" * 32,
        "endpoints": ["wss://asia-southeast-1.vortex.sol:9000",
                      "http://cc7vortex4asianode9.onion",
                      "ipfs://bafybeinodeCC-static"],
        "metadata": {"name": "node-C (pan-continental)", "region": "asia-se", "version": "1.0.1"},
        "last_seen": NOW - 60 * 60 * 24 * 14,
        "sealed": True, "weight": 0.5,
    },
    # Unsealed (never called seal()) — caps weight at 0.5
    {
        "pubkey":   "dd" * 32,
        "endpoints": ["wss://home-nat-jitter.trycloudflare.com"],
        "metadata": {"name": "home-pi", "region": "self", "version": "0.9-rc"},
        "last_seen": NOW - 60 * 10,
        "sealed": False, "weight": 0.5,
    },
    # Stale on-chain sealed node — weight 0.2
    {
        "pubkey":   "ee" * 32,
        "endpoints": ["wss://dusty-corner.vortex.example:9000"],
        "metadata": {"name": "legacy-node", "region": "eu-central", "version": "0.8.4"},
        "last_seen": NOW - 60 * 60 * 24 * 120,
        "sealed": True, "weight": 0.2,
    },
    # Solana-only (discovered on-chain, no controller record) — dual-verified
    {
        "pubkey":   "11" * 32,
        "endpoints": ["wss://solana-only-demo.trycloudflare.com"],
        "metadata": {"name": "solana-only", "region": "unknown", "sealed": True,
                     "code_hash": "feedfacecafebeef" + "00" * 24},
        "last_seen": NOW - 90,
        "sealed": True, "weight": 1.0,
        "code_hash": "feedfacecafebeef" + "00" * 24,
    },
    # Controller-only
    {
        "pubkey":   "22" * 32,
        "endpoints": ["wss://controller-only.vortex.example"],
        "metadata": {"name": "ctrl-only", "version": "1.0.0"},
        "last_seen": NOW - 30,
        "sealed": False, "weight": 0.9,
    },
    # Unverified bootstrap peer
    {
        "pubkey":   "33" * 32,
        "endpoints": ["wss://bootstrap-seed.vortex.example"],
        "metadata": {"name": "bootstrap-seed"},
        "last_seen": NOW - 5,
        "sealed": False, "weight": 0.7,
    },
]

STATS = {
    "total":    len(PEERS) + 12,   # + unlisted (stale) records on the fake registry
    "approved": len(PEERS) + 4,
    "online":   sum(1 for p in PEERS if NOW - p["last_seen"] < 300),
}


# ── App ───────────────────────────────────────────────────────────────────

app = FastAPI(title="vortex-test preview", docs_url=None, redoc_url=None, openapi_url=None)

# /static/* → public/assets (css, js); fall back to public/ if assets dir missing.
_assets_dir = PUBLIC / "assets"
if _assets_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(_assets_dir)), name="static")
else:
    app.mount("/static", StaticFiles(directory=str(PUBLIC)), name="static")

app.mount("/locales", StaticFiles(directory=str(PUBLIC / "locales")), name="locales")

# Multi-page routing — each URL maps to its own HTML file.
PAGES = {
    "/":         "index.html",
    "/nodes":    "nodes.html",
    "/entries":  "entries.html",
    "/mirrors":  "mirrors.html",
    "/security": "security.html",
}


def _make_page_handler(file_name: str):
    async def _handler():
        return FileResponse(PUBLIC / file_name)
    return _handler


for _path, _file in PAGES.items():
    app.add_api_route(
        _path, _make_page_handler(_file),
        methods=["GET"], include_in_schema=False,
    )


@app.get("/favicon.ico", include_in_schema=False)
async def _favicon():
    return FileResponse(PUBLIC / "favicon.ico")


# ── API endpoints (signed where the website expects signatures) ──────────

@app.get("/v1/health")
async def health():
    return {
        "status":  "ok",
        "version": "0.1.0-preview",
        "pubkey":  _PUB_HEX,
        "stats":   STATS,
    }


@app.get("/v1/integrity")
async def integrity():
    # Fake but structurally identical to real /v1/integrity response
    return {
        "status":         "verified",
        "signed_by":      _PUB_HEX,
        "trusted_pubkey": _PUB_HEX,
        "version":        "0.1.0-preview",
        "built_at":       START - 3600,
        "matched":        158,
        "mismatched":     [],
        "missing":        [],
        "extra":          [],
        "message":        "All 158 files match manifest v0.1.0-preview (signed by preview key)",
    }


@app.get("/v1/entries")
async def entries():
    payload = {
        "entries":     ENTRY_URLS,
        "issued_at":   NOW,
        "valid_until": NOW + 3600,
    }
    return sign_envelope(payload)


@app.get("/v1/mirrors")
async def mirrors():
    items = []
    for m in MIRRORS:
        e = {"url": m["url"], "type": m["type"]}
        if m.get("healthy") is not None:
            e["healthy"] = m["healthy"]
            e["latency_ms"] = m["latency_ms"]
            e["last_checked"] = m["last_checked"]
            if m.get("error"):
                e["error"] = m["error"]
        items.append(e)
    payload = {"mirrors": items, "issued_at": NOW, "valid_until": NOW + 86400}
    return sign_envelope(payload)


@app.get("/v1/mirrors/health")
async def mirrors_health():
    return {
        "last_sweep": NOW - 5,
        "mirrors": [
            {
                "url":          m["url"],
                "ok":           bool(m.get("healthy")),
                "last_checked": m.get("last_checked", 0),
                "latency_ms":   m.get("latency_ms"),
                "error":        m.get("error"),
            }
            for m in MIRRORS
        ],
    }


@app.get("/v1/nodes/random")
async def nodes_random(count: int = 5):
    chosen = PEERS[: max(1, min(count, len(PEERS)))]
    payload = {"nodes": chosen, "count": len(chosen)}
    return sign_envelope(payload)


@app.get("/v1/nodes/lookup/{pubkey}")
async def nodes_lookup(pubkey: str):
    pubkey = pubkey.lower()
    for p in PEERS:
        if p["pubkey"] == pubkey:
            return sign_envelope({"node": p})
    return JSONResponse({"detail": "node not found"}, status_code=404)


# ── Main ─────────────────────────────────────────────────────────────────

def main() -> None:
    host = "127.0.0.1"
    port = 7700
    print(f"Vortex preview (fake data) running at:  http://{host}:{port}")
    print(f"Signing key (regenerates on every launch): {_PUB_HEX}")
    uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()

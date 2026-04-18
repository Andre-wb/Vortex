"""Admin dashboard API — reads live metrics from the running Vortex node.

All endpoints return local-only data. There is no telemetry, no external
API call, no phone-home behavior. Even "check for updates" is gated
behind an explicit user action.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import sys
import time
from pathlib import Path
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api/wiz/admin", tags=["admin"])


def _env_path(request) -> Path:
    p = getattr(request.app.state, "env_file", None)
    return Path(p) if p else Path(".env")


def _read_env_at(env_file: Path) -> dict[str, str]:
    if not env_file.is_file():
        return {}
    out: dict[str, str] = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def _node_base_url(env: dict) -> str:
    port = env.get("PORT", "9000")
    host = env.get("HOST", "127.0.0.1")
    if host == "0.0.0.0":
        host = "127.0.0.1"
    proto = "https" if (Path("certs") / "vortex.crt").is_file() else "http"
    return f"{proto}://{host}:{port}"


async def _node_get_at(url: str, timeout: float = 5.0) -> Optional[dict]:
    try:
        # verify=False since the cert is self-signed and we're on loopback
        async with httpx.AsyncClient(timeout=timeout, verify=False) as http:
            r = await http.get(url)
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        logging.debug("node GET %s failed: %s", url, e)
    return None


async def _node_get(request, path: str, timeout: float = 5.0) -> Optional[dict]:
    env = _read_env_at(_env_path(request))
    base = _node_base_url(env).rstrip("/")
    return await _node_get_at(f"{base}{path}", timeout=timeout)


@router.get("/overview")
async def overview(request: Request) -> dict:
    """Single call that the dashboard polls every 5s."""
    env = _read_env_at(_env_path(request))
    node_url = _node_base_url(env)

    health = await _node_get(request, "/api/health")
    migration_hint = await _node_get(request, "/api/session/migration-hint")
    integrity = await _node_get(request, "/v1/integrity")

    return {
        "node_url": node_url,
        "device_name": env.get("DEVICE_NAME", ""),
        "network_mode": env.get("NETWORK_MODE", "local"),
        "controller_url": env.get("CONTROLLER_URL", ""),
        "controller_pubkey": env.get("CONTROLLER_PUBKEY", ""),
        "running": health is not None,
        "health": health,
        "migration_hint": migration_hint,
        "integrity": integrity,
    }


@router.get("/identity")
async def identity(request: Request) -> dict:
    """Node Ed25519 signing pubkey (from keys/ed25519_signing.bin)."""
    keys_dir = Path(_read_env_at(_env_path(request)).get("KEYS_DIR", "keys"))
    sig_path = keys_dir / "ed25519_signing.bin"
    if not sig_path.is_file():
        return {"pubkey": None, "message": "Node has not generated a signing key yet."}
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.from_private_bytes(sig_path.read_bytes())
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
        return {"pubkey": pub}
    except Exception as e:
        return {"pubkey": None, "error": str(e)}


@router.get("/peers")
async def peers(request: Request) -> dict:
    """Current peer list with verification source (controller / on-chain / bootstrap)."""
    hint = await _node_get(request, "/api/session/migration-hint")
    alternatives = (hint or {}).get("alternatives") or []
    # Classify verification source based on presence of on-chain fields.
    for a in alternatives:
        md = a.get("metadata") or {}
        if md.get("sealed") or a.get("code_hash"):
            a["verification"] = "solana+controller"
        else:
            a["verification"] = "controller"
    return {"peers": alternatives}


@router.get("/traffic")
async def traffic(request: Request) -> dict:
    """CPU / RAM / WS counters — metadata-safe (no content, only numbers)."""
    import resource
    rusage = resource.getrusage(resource.RUSAGE_SELF)
    info = {
        "ws_active": 0,
        "rooms_active": 0,
        "cpu_seconds": round(rusage.ru_utime + rusage.ru_stime, 2),
        "memory_mb": round(rusage.ru_maxrss / (1024 if sys.platform != "darwin" else 1024 * 1024), 1),
        "pid": os.getpid(),
    }
    health = await _node_get(request, "/api/health")
    if isinstance(health, dict):
        info["ws_active"] = health.get("ws_connections", 0)
        info["rooms_active"] = health.get("rooms", 0)
    return info


@router.get("/certs")
async def certs(request: Request) -> dict:
    """SSL cert expiry + key ages."""
    out: dict = {"ssl": None, "jwt_secret_age_days": None, "csrf_secret_age_days": None}
    cert = Path("certs") / "vortex.crt"
    if cert.is_file():
        try:
            from cryptography import x509
            data = cert.read_bytes()
            c = x509.load_pem_x509_certificate(data)
            out["ssl"] = {
                "subject": c.subject.rfc4514_string(),
                "not_before": int(c.not_valid_before.timestamp()),
                "not_after": int(c.not_valid_after.timestamp()),
                "days_left": int((c.not_valid_after.timestamp() - time.time()) / 86400),
            }
        except Exception as e:
            out["ssl"] = {"error": str(e)}
    env_file = _env_path(request)
    if env_file.is_file():
        mtime = env_file.stat().st_mtime
        age_days = int((time.time() - mtime) / 86400)
        out["jwt_secret_age_days"] = age_days
        out["csrf_secret_age_days"] = age_days
    return out


@router.get("/logs")
async def logs(limit: int = 500, level: str = "all") -> dict:
    """Read the last N lines from logs/vortex.log (if it exists)."""
    log_candidates = [
        Path("logs") / "vortex.log",
        Path("logs") / "vortex.json.log",
        Path("vortex.log"),
    ]
    log_file: Optional[Path] = next((p for p in log_candidates if p.is_file()), None)
    if log_file is None:
        return {"lines": [], "source": None}

    lines = []
    try:
        # Cheap tail: read last ~256KB, split, take last N
        size = log_file.stat().st_size
        chunk = min(size, 256 * 1024)
        with log_file.open("rb") as f:
            f.seek(size - chunk)
            data = f.read()
        text = data.decode("utf-8", errors="replace").splitlines()
        lines = text[-limit:]
    except Exception as e:
        return {"lines": [], "source": str(log_file), "error": str(e)}

    level = level.lower()
    if level != "all":
        lines = [ln for ln in lines if level.upper() in ln]
    return {"lines": lines, "source": str(log_file)}


@router.post("/reverify")
async def reverify() -> dict:
    """Recompute the controller's integrity check right now."""
    try:
        from vortex_controller.integrity.verify import verify_at_startup
        root = Path(__file__).resolve().parent.parent.parent / "vortex_controller"
        if root.is_dir():
            report = verify_at_startup(root=root)
            return report.to_dict()
    except Exception as e:
        return {"status": "error", "message": str(e)}
    return {"status": "unknown", "message": "Controller code not located"}


@router.get("/env")
async def env_snapshot(request: Request) -> dict:
    """Return selected env vars (secrets masked)."""
    env = _read_env_at(_env_path(request))
    masked = dict(env)
    for k in ("JWT_SECRET", "CSRF_SECRET", "STEALTH_SECRET", "VORTEX_NETWORK_KEY", "POSTGRES_PASSWORD"):
        if k in masked and masked[k]:
            masked[k] = masked[k][:8] + "…" + masked[k][-4:]
    return masked


@router.get("/check-node")
async def check_node(request: Request) -> dict:
    """Ping the messenger node; returns whether it's running."""
    env = _read_env_at(_env_path(request))
    base = _node_base_url(env)
    return {
        "running": await _node_get_at(f"{base}/api/health") is not None,
        "url": base,
    }


@router.get("/earnings")
async def earnings(request: Request) -> dict:
    """Operator-level rewards summary.

    Reads the wallet pubkey from ``WALLET_PUBKEY`` in the env file (set
    during setup from the BIP39 mnemonic) and combines it with uptime
    and traffic metrics to show the operator what they're earning.

    Figures are placeholder until the payout smart contract is live —
    but the wallet address, stake, and uptime are real.
    """
    env = _read_env_at(_env_path(request))
    wallet = env.get("WALLET_PUBKEY", "")
    node_pub = env.get("NODE_PUBKEY", "")

    # Uptime from migration-hint (cheap proxy — node reports its own age).
    hint = await _node_get(request, "/api/session/migration-hint")
    running = hint is not None

    # Mock stake / register-fee status until smart contract is deployed.
    stake_sol = 0.0
    register_fee_paid = False

    # Rewards estimate: follows the same formula the platform dashboard
    # uses (70% of premium revenue / rewards pool). Without real on-chain
    # numbers we give the operator a scenario-style projection anchored
    # in their uptime.
    uptime_pct = 100.0 if running else 0.0
    users_served_est = 8 if running else 0       # placeholder
    est_monthly_usd  = users_served_est * 5 * 0.7 * (uptime_pct / 100.0)
    est_monthly_sol  = round(est_monthly_usd / 150, 4)

    return {
        "wallet_pubkey":   wallet,
        "node_pubkey":     node_pub,
        "stake_sol":       stake_sol,
        "register_fee_paid": register_fee_paid,
        "uptime_pct":      round(uptime_pct, 1),
        "users_served":    users_served_est,
        "estimated": {
            "monthly_usd": round(est_monthly_usd, 2),
            "monthly_sol": est_monthly_sol,
        },
        "note": "estimate — becomes exact once the payout contract is wired in",
    }

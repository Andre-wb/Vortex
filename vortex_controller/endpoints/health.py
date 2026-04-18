"""GET /v1/health — liveness and stats."""
from __future__ import annotations

from fastapi import APIRouter, Request

from .. import VERSION
from ..models import HealthResponse

router = APIRouter(prefix="/v1", tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    storage = request.app.state.storage
    key = request.app.state.controller_key
    return HealthResponse(
        status="ok",
        version=VERSION,
        pubkey=key.pubkey_hex(),
        stats=await storage.stats(),
    )


@router.get("/treasury")
async def treasury(request: Request) -> dict:
    """Public-facing treasury metadata — the Solana wallet that receives
    register fees + the protocol cut of premium subscriptions.

    Publishing it here means any client can verify on-chain that their
    payment actually landed at the address advertised by this controller.
    """
    return {
        "pubkey":       getattr(request.app.state, "treasury_pubkey", "") or "",
        "chain":        "solana",
        "sns_domain":   "vortexx.sol",
        "fee_schedule": {
            "register_fee_sol":    1.0,
            "premium_protocol_pct": 20,
        },
    }

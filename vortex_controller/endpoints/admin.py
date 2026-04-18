"""Platform-admin revenue dashboard (bearer-token auth).

Exposes a single private endpoint, ``GET /admin/revenue``, guarded by a
secret token configured via ``ADMIN_TOKEN``. It reports protocol-level
money flows: how much the treasury received, how many premium subs are
active, how much was distributed to node operators.

This is the **platform owner** view — one account, not per-operator.
Each node operator sees their own rewards in their wizard admin panel.

Numbers are mock/derived today because the payout smart contract is
not yet live. Schema is stable so frontend code doesn't have to change
when we wire to real on-chain reads.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/admin", tags=["admin"])


def _require_admin(request: Request) -> None:
    """Reject requests without a matching bearer token.

    When ``ADMIN_TOKEN`` is empty the whole admin surface stays disabled —
    a forgotten default credential can't become an accidental back door.
    """
    expected = (getattr(request.app.state, "admin_token", "") or "").strip()
    if not expected:
        raise HTTPException(503, "admin interface is not configured")
    got = (request.headers.get("authorization") or "").strip()
    if not got.lower().startswith("bearer "):
        raise HTTPException(401, "bearer token required")
    token = got[7:].strip()
    if token != expected:
        raise HTTPException(403, "invalid admin token")


@router.get("/whoami")
async def whoami(request: Request) -> dict:
    _require_admin(request)
    return {
        "authenticated": True,
        "treasury_pubkey": getattr(request.app.state, "treasury_pubkey", ""),
    }


@router.get("/revenue")
async def revenue(request: Request) -> dict:
    """Revenue snapshot for the platform owner.

    Returned fields:
      * treasury_balance_sol   — current wallet balance (on-chain)
      * register_fees_30d      — count + total SOL from register events
      * premium_subs_active    — distinct paying users right now
      * mrr_usd                — current monthly recurring revenue
      * rewards_distributed_30d — SOL paid out to operators in last 30d
      * daily_inflow_30d       — 30-long array of daily inflow (SOL)
                                 for a simple SVG sparkline on the page
      * fee_schedule           — same as /v1/treasury for quick reference
    """
    _require_admin(request)

    storage = request.app.state.storage
    stats = await storage.stats()

    registered_total = int(stats.get("total", 0))
    approved_total = int(stats.get("approved", 0))
    online_total = int(stats.get("online", 0))

    # Mock numbers until the payout smart contract is live. Derived from
    # current network size so the UI feels real during testing.
    register_fee_sol = 1.0
    register_fees_30d_count = max(0, registered_total // 3)
    register_fees_30d_sol = register_fees_30d_count * register_fee_sol

    # ~10% of approved nodes have premium users on them, average 8 per node.
    premium_subs_active = approved_total * 8 // 10
    price_per_month_usd = 5
    mrr_usd = premium_subs_active * price_per_month_usd

    # 70% of subscription revenue distributed to operators.
    rewards_distributed_30d_usd = int(mrr_usd * 0.7)
    # Rough $/SOL for preview; real deployment should fetch from an oracle.
    sol_usd = 150
    rewards_distributed_30d_sol = round(rewards_distributed_30d_usd / sol_usd, 3)

    daily_inflow_30d = []
    seed = (registered_total + 7) % 97 or 13
    for day in range(30):
        x = (seed * (day + 1)) % 23
        daily_inflow_30d.append(round(0.3 + x * 0.18, 2))

    return {
        "treasury_pubkey":            getattr(request.app.state, "treasury_pubkey", ""),
        "treasury_balance_sol":       round(sum(daily_inflow_30d), 3),
        "register_fees_30d": {
            "count": register_fees_30d_count,
            "sol":   register_fees_30d_sol,
        },
        "premium_subs_active":        premium_subs_active,
        "mrr_usd":                    mrr_usd,
        "rewards_distributed_30d_sol": rewards_distributed_30d_sol,
        "rewards_distributed_30d_usd": rewards_distributed_30d_usd,
        "network": {
            "registered": registered_total,
            "approved":   approved_total,
            "online":     online_total,
        },
        "daily_inflow_30d":           daily_inflow_30d,
        "fee_schedule": {
            "register_fee_sol":     register_fee_sol,
            "premium_protocol_pct": 20,
            "premium_rewards_pct":  70,
            "premium_burn_pct":     10,
            "price_per_month_usd":  price_per_month_usd,
        },
        "issued_at": int(time.time()),
        "note":      "mock figures — replaces with on-chain reads once payout contract is live",
    }

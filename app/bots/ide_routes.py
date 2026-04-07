"""
app/bots/ide_routes.py — Thin re-export hub for all IDE route modules.

Maintains backward compatibility with main.py imports:
    from app.bots.ide_routes import (
        router as ide_router,
        bot_call_router as ide_bot_call_router,
        federated_router as ide_federated_router,
        webhook_router as ide_webhook_router,
    )

The actual endpoint logic is split across:
    ide_projects.py    — compile, publish, status, logs, stop, test, AI proxy
    ide_versioning.py  — versioning, rollback, flow graph
    ide_monitoring.py  — analytics, metrics, queues, audit, breakers, packages,
                         admin, webhooks list, permissions
    ide_bot_api.py     — inter-bot calls, chat actions, notifications, forms,
                         federation, webhook forwarding
    ide_shared.py      — shared constants, helpers, request models
"""
from __future__ import annotations

from fastapi import APIRouter

# ── Import sub-module routers ─────────────────────────────────────────────
from app.bots.ide_projects import router as _projects_router
from app.bots.ide_versioning import router as _versioning_router
from app.bots.ide_monitoring import router as _monitoring_router
from app.bots.ide_bot_api import (
    bot_call_router,
    federated_router,
    webhook_router,
)

# ── Re-export shared symbols used by tests ────────────────────────────────
from app.bots.ide_shared import (  # noqa: F401
    CompileRequest,
    PublishRequest,
    _validate_id,
)

# ── Merge all /api/ide sub-routers into a single router ──────────────────
# Each sub-module defines its own APIRouter(prefix="/api/ide", tags=["ide"]).
# We include them into a parent router so main.py sees a single `router`.
router = APIRouter()
router.include_router(_projects_router)
router.include_router(_versioning_router)
router.include_router(_monitoring_router)

# ── Public exports (consumed by main.py) ─────────────────────────────────
__all__ = [
    "router",
    "bot_call_router",
    "federated_router",
    "webhook_router",
    "CompileRequest",
    "PublishRequest",
    "_validate_id",
]

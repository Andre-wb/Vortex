"""
app/bots/ide_monitoring.py — Monitoring, analytics, admin, and configuration endpoints.

GET  /api/ide/analytics/{pid}              bot analytics
GET  /api/ide/metrics/{pid}                bot metrics + A/B results
GET  /api/ide/queues/{pid}                 bot job queue status
GET  /api/ide/audit/{pid}                  bot audit trail
GET  /api/ide/breakers/{pid}               circuit breaker states
GET  /api/ide/packages                     list available packages
POST /api/ide/packages/install             install a package
GET  /api/ide/admin/{pid}                  bot admin panel config
GET  /api/ide/webhooks/{pid}               registered webhooks
GET  /api/ide/permissions/{pid}            RBAC permissions config
POST /api/ide/permissions/{pid}/assign     assign a role to a user
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Depends

from app.models import User
from app.security.auth_jwt import get_current_user
from app.bots.ide_runner import get_logs, get_status
from app.bots.ide_shared import _BASE, _validate_id


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ide", tags=["ide"])


# ── Analytics ─────────────────────────────────────────────────────────────

@router.get("/analytics/{project_id}")
async def bot_analytics(project_id: str, current_user: User = Depends(get_current_user)):
    """Return analytics for a bot project (log-based + track()-based events)."""
    pid = _validate_id(project_id)
    status = get_status(pid)
    logs = get_logs(pid, last_n=500)

    # Parse logs for metrics
    message_count = sum(1 for l in logs if "message" in l.lower() or "emit" in l.lower() or "send" in l.lower())
    error_count = sum(1 for l in logs if "error" in l.lower() or "ERROR" in l)
    command_count = sum(1 for l in logs if "command" in l.lower() or "/start" in l or "/help" in l)
    callback_count = sum(1 for l in logs if "callback" in l.lower())

    # Recent log lines (last 50)
    recent_logs = logs[-50:] if len(logs) > 50 else logs

    # Round-7: track() events from analytics file
    analytics_file = _BASE / "bots_workspace" / f"{pid}_analytics.json"
    events: list = []
    summary: dict = {}
    if analytics_file.exists():
        try:
            events = json.loads(analytics_file.read_text())
            for e in events:
                name = e.get("name", "unknown")
                summary[name] = summary.get(name, 0) + 1
            events = events[-500:]
        except Exception:
            pass

    return {
        "project_id": pid,
        "ok": True,
        "status": status,
        "metrics": {
            "messages_processed": message_count,
            "errors": error_count,
            "commands_processed": command_count,
            "callbacks_processed": callback_count,
            "total_log_lines": len(logs),
        },
        "recent_logs": recent_logs,
        "uptime_seconds": status.get("uptime"),
        "events": events,
        "summary": summary,
    }


# ── Metrics ───────────────────────────────────────────────────────────────

@router.get("/metrics/{project_id}")
async def get_bot_metrics(
    project_id: str,
    current_user: User = Depends(get_current_user),
):
    """Read bot metrics exported by Gravitix runtime."""
    pid = _validate_id(project_id)

    BASE = Path(__file__).resolve().parent.parent.parent
    metrics_file = BASE / "bots_workspace" / f"{pid}_metrics.json"
    ab_file = BASE / "bots_workspace" / f"{pid}_ab.json"

    metrics: dict = {}
    ab_results: dict = {}

    if metrics_file.exists():
        try:
            metrics = json.loads(metrics_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    if ab_file.exists():
        try:
            ab_results = json.loads(ab_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    return {"ok": True, "metrics": metrics, "ab_results": ab_results}


# ── Queue monitoring ─────────────────────────────────────────────────────

@router.get("/queues/{project_id}")
async def get_bot_queues(
    project_id: str,
    current_user: User = Depends(get_current_user),
):
    """Get status of bot job queues."""
    pid = _validate_id(project_id)
    queues_file = _BASE / "bots_workspace" / f"{pid}_queues.json"
    if queues_file.exists():
        try:
            data = json.loads(queues_file.read_text(encoding="utf-8"))
            return {"ok": True, "queues": data}
        except Exception:
            pass
    return {"ok": True, "queues": {}}


# ── Audit log ─────────────────────────────────────────────────────────────

@router.get("/audit/{project_id}")
async def get_bot_audit(
    project_id: str,
    n: int = 50,
    current_user: User = Depends(get_current_user),
):
    """Get bot audit trail entries."""
    pid = _validate_id(project_id)
    audit_file = _BASE / "bots_workspace" / f"{pid}_audit.json"
    if audit_file.exists():
        try:
            entries = json.loads(audit_file.read_text(encoding="utf-8"))
            return {"ok": True, "entries": entries[-n:]}
        except Exception:
            pass
    return {"ok": True, "entries": []}


# ── Circuit breaker status ───────────────────────────────────────────────

@router.get("/breakers/{project_id}")
async def get_breaker_status(project_id: str, user=Depends(get_current_user)):
    """Get circuit breaker states for a bot."""
    _validate_id(project_id)
    breaker_file = _BASE / "bots_workspace" / f"{project_id}_breakers.json"
    if not breaker_file.exists():
        return {"ok": True, "breakers": {}}
    try:
        data = json.loads(breaker_file.read_text())
        return {"ok": True, "breakers": data}
    except Exception:
        return {"ok": True, "breakers": {}}


# ── Package registry ─────────────────────────────────────────────────────

@router.get("/packages")
async def list_packages(user=Depends(get_current_user)):
    """List available Gravitix packages."""
    packages = [
        {"name": "antispam", "version": "1.0", "description": "Auto-moderation: flood, spam, links"},
        {"name": "translate", "version": "1.0", "description": "Multi-language auto-translation"},
        {"name": "ai-tools", "version": "1.0", "description": "AI helpers: summarize, classify, sentiment"},
        {"name": "analytics", "version": "1.0", "description": "User tracking and funnel analysis"},
        {"name": "welcome", "version": "1.0", "description": "Customizable welcome flows"},
        {"name": "moderation", "version": "1.0", "description": "Advanced moderation toolkit"},
        {"name": "games", "version": "1.0", "description": "Mini-games: quiz, trivia, polls"},
        {"name": "scheduler", "version": "1.0", "description": "Advanced scheduling helpers"},
    ]
    return {"ok": True, "packages": packages}


@router.post("/packages/install")
async def install_package(body: dict, user=Depends(get_current_user)):
    """Install a package for a project."""
    project_id = body.get("project_id", "")
    package_name = body.get("package", "")
    _validate_id(project_id)

    plugins_dir = _BASE / "bots_workspace" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)

    stub = f'// Gravitix package: {package_name}\n// Auto-installed via IDE\n\nfn {package_name}_init() {{\n    log("Plugin {package_name} loaded")\n}}\n'
    (plugins_dir / f"{package_name}.grav").write_text(stub, encoding="utf-8")

    return {"ok": True, "installed": package_name, "path": f"plugins/{package_name}.grav"}


# ── Admin panel ───────────────────────────────────────────────────────────

@router.get("/admin/{project_id}")
async def get_bot_admin(project_id: str, user=Depends(get_current_user)):
    """Get bot admin panel configuration."""
    _validate_id(project_id)
    admin_file = _BASE / "bots_workspace" / f"{project_id}_admin.json"
    if not admin_file.exists():
        return {"ok": False, "error": "No admin panel defined"}
    try:
        config = json.loads(admin_file.read_text())
        return {"ok": True, "admin": config}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Webhook registration ─────────────────────────────────────────────────

@router.get("/webhooks/{project_id}")
async def get_webhooks(project_id: str, user=Depends(get_current_user)):
    """Get registered webhooks for a bot."""
    _validate_id(project_id)
    wh_file = _BASE / "bots_workspace" / f"{project_id}_webhooks.json"
    if not wh_file.exists():
        return {"ok": True, "webhooks": []}
    try:
        data = json.loads(wh_file.read_text())
        return {"ok": True, "webhooks": data}
    except Exception:
        return {"ok": True, "webhooks": []}


# ── Permissions management ───────────────────────────────────────────────

@router.get("/permissions/{project_id}")
async def get_permissions(project_id: str, user=Depends(get_current_user)):
    """Get RBAC permissions config for a bot."""
    _validate_id(project_id)
    perm_file = _BASE / "bots_workspace" / f"{project_id}_permissions.json"
    if not perm_file.exists():
        return {"ok": True, "permissions": None}
    try:
        return {"ok": True, "permissions": json.loads(perm_file.read_text())}
    except Exception:
        return {"ok": True, "permissions": None}


@router.post("/permissions/{project_id}/assign")
async def assign_role(project_id: str, body: dict, user=Depends(get_current_user)):
    """Assign a role to a user."""
    _validate_id(project_id)
    user_id = body.get("user_id", 0)
    role = body.get("role", "user")

    roles_file = _BASE / "bots_workspace" / f"{project_id}_roles.json"
    roles = {}
    if roles_file.exists():
        try:
            roles = json.loads(roles_file.read_text())
        except Exception:
            pass
    roles[str(user_id)] = role
    roles_file.write_text(json.dumps(roles), encoding="utf-8")
    return {"ok": True, "user_id": user_id, "role": role}

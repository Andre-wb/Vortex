"""
app/bots/ide_versioning.py — Versioning, rollback, and visual flow graph.

GET  /api/ide/versions/{pid}        list saved versions
POST /api/ide/save/{pid}            save current code as new version
POST /api/ide/rollback/{pid}/{v}    restore version N
GET  /api/ide/graph/{pid}           return graph {nodes, edges} extracted from code
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from app.models import User
from app.security.auth_jwt import get_current_user
from app.bots.ide_runner import _BOTS_DIR
from app.bots.ide_shared import SaveVersionRequest, _validate_id


router = APIRouter(prefix="/api/ide", tags=["ide"])

_MAX_VERSIONS = 20


# ── Versioning helpers ────────────────────────────────────────────────────

def _versions_path(project_id: str) -> Path:
    _BOTS_DIR.mkdir(parents=True, exist_ok=True)
    return _BOTS_DIR / f"{project_id}_versions.json"


def _load_versions(project_id: str) -> list:
    p = _versions_path(project_id)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_versions(project_id: str, versions: list) -> None:
    _versions_path(project_id).write_text(
        json.dumps(versions, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


# ── Graph extraction ─────────────────────────────────────────────────────

def _extract_graph(code: str) -> dict:
    """Regex-based graph extraction from Gravitix source."""
    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: set[str] = set()

    def _add_node(node_id: str, label: str, node_type: str) -> None:
        if node_id not in node_ids:
            node_ids.add(node_id)
            nodes.append({"id": node_id, "label": label, "type": node_type})

    # Command / event handlers:  on /cmd  on msg  on join  on leave  etc.
    for m in re.finditer(
        r'on\s+((/\w+)|msg|join|leave|callback|photo|voice|reaction\s+"[^"]*")',
        code,
    ):
        label = m.group(1).strip()
        node_id = f"handler_{m.start()}"
        _add_node(node_id, label, "handler")

    # Flow definitions:  flow foo { ... }
    for m in re.finditer(r'\bflow\s+(\w+)', code):
        node_id = f"flow_{m.group(1)}"
        _add_node(node_id, m.group(1), "flow")

    # Function definitions:  fn foo( ...
    for m in re.finditer(r'\bfn\s+(\w+)\s*\(', code):
        node_id = f"fn_{m.group(1)}"
        _add_node(node_id, f"fn {m.group(1)}()", "function")

    # State block or state var
    if re.search(r'\bstate\s*\{', code):
        _add_node("state_block", "state {}", "state")
    for m in re.finditer(r'\bstate\s+(\w+)\s*=', code):
        node_id = f"state_{m.group(1)}"
        _add_node(node_id, f"state.{m.group(1)}", "state")

    # Edges:  run flow X
    for m in re.finditer(r'\brun\s+flow\s+(\w+)', code):
        target_id = f"flow_{m.group(1)}"
        edges.append({"from": "current", "to": target_id, "label": "run flow"})

    # Edges: function calls (fn_name(...) where fn_name is a known fn node)
    fn_names = {n["label"].split("(")[0][3:] for n in nodes if n["type"] == "function"}
    for fname in fn_names:
        call_re = re.compile(r'\b' + re.escape(fname) + r'\s*\(')
        # find all calls outside the fn definition itself
        for m in call_re.finditer(code):
            # Skip the definition line
            line_start = code.rfind('\n', 0, m.start()) + 1
            line = code[line_start: code.find('\n', m.start())]
            if re.match(r'\s*fn\s+', line):
                continue
            edges.append({"from": "caller", "to": f"fn_{fname}", "label": "call"})
            break  # one edge per function is enough

    return {"nodes": nodes, "edges": edges}


# ── Versioning endpoints ─────────────────────────────────────────────────

@router.get("/versions/{project_id}")
async def ide_list_versions(
    project_id: str,
    current_user: User = Depends(get_current_user),
):
    """Return all saved versions for a project (newest first)."""
    pid = _validate_id(project_id)
    versions = _load_versions(pid)
    # Return metadata only (no code) to keep response small
    return {
        "project_id": pid,
        "versions": [
            {
                "version": v["version"],
                "saved_at": v["saved_at"],
                "size": len(v.get("code", "")),
            }
            for v in reversed(versions)
        ],
    }


@router.post("/save/{project_id}")
async def ide_save_version(
    project_id: str,
    body: SaveVersionRequest,
    current_user: User = Depends(get_current_user),
):
    """Save current code as a new version (auto-incremented).  Keeps max 20."""
    pid = _validate_id(project_id)
    versions = _load_versions(pid)

    next_v = (versions[-1]["version"] + 1) if versions else 1
    entry = {
        "version": next_v,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "code": body.code,
    }
    versions.append(entry)
    # Trim to max 20 — keep newest
    if len(versions) > _MAX_VERSIONS:
        versions = versions[-_MAX_VERSIONS:]

    _save_versions(pid, versions)
    return {
        "ok": True,
        "version": next_v,
        "saved_at": entry["saved_at"],
        "total_versions": len(versions),
    }


@router.post("/rollback/{project_id}/{version}")
async def ide_rollback_version(
    project_id: str,
    version: int,
    current_user: User = Depends(get_current_user),
):
    """Restore version N as the current code.  Returns the code for the frontend to load."""
    pid = _validate_id(project_id)
    versions = _load_versions(pid)
    entry = next((v for v in versions if v["version"] == version), None)
    if entry is None:
        raise HTTPException(404, f"Version {version} not found for project {pid}")

    # Write the restored code to the main .grav file so it's consistent on disk
    from app.bots.ide_runner import _script_path
    _script_path(pid).write_text(entry["code"], encoding="utf-8")

    return {
        "ok": True,
        "version": version,
        "saved_at": entry["saved_at"],
        "code": entry["code"],
    }


# ── Visual Flow Graph ────────────────────────────────────────────────────

@router.get("/graph/{project_id}")
async def ide_flow_graph(
    project_id: str,
    current_user: User = Depends(get_current_user),
):
    """Extract and return a flow graph (nodes + edges) from the project's .grav file."""
    pid = _validate_id(project_id)
    from app.bots.ide_runner import _script_path
    path = _script_path(pid)
    if not path.exists():
        return {"project_id": pid, "nodes": [], "edges": []}
    code = path.read_text(encoding="utf-8")
    graph = _extract_graph(code)
    graph["project_id"] = pid
    return graph

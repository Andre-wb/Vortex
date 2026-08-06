"""
app/bots/ide_shared.py — Shared constants, models, and helpers for IDE routes.
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field

_BASE = Path(__file__).resolve().parent.parent.parent

_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")


def _validate_id(pid: str) -> str:
    if not _ID_RE.match(pid):
        raise HTTPException(400, "Invalid project_id")
    return pid


# IDE "projects" are just files in the shared bots_workspace/ directory keyed by
# a free-chosen project_id. There is no DB row, so we maintain a lightweight
# pid -> owner_user_id map on disk and enforce it on every request. This closes
# the IDOR/BOLA where any authenticated user could read/overwrite/kill another
# user's bot code by guessing its project_id.

_OWNERSHIP_LOCK = threading.Lock()


def _ownership_path() -> Path:
    d = _BASE / "bots_workspace"
    d.mkdir(parents=True, exist_ok=True)
    return d / ".ownership.json"


def _load_ownership() -> dict:
    p = _ownership_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_ownership(data: dict) -> None:
    path = _ownership_path()
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(path)


def _require_project(pid: str, user, *, create: bool = False) -> str:
    """Validate ``pid`` and enforce that ``user`` owns the project.

    - ``create=True`` (write / first-touch ops): if the project is unclaimed it
      is claimed for ``user`` (trust-on-first-use). If owned by someone else a
      404 is raised (don't reveal existence).
    - ``create=False`` (read ops): the project must already be owned by ``user``;
      otherwise 404.

    Always returns the validated pid so callers keep their existing flow.
    """
    _validate_id(pid)
    uid = getattr(user, "id", None)
    if uid is None:
        # Should never happen behind get_current_user, but fail closed.
        raise HTTPException(401, "Authentication required")

    with _OWNERSHIP_LOCK:
        owners = _load_ownership()
        owner = owners.get(pid)
        if owner is None:
            if create:
                owners[pid] = uid
                _save_ownership(owners)
                return pid
            raise HTTPException(404, "Project not found")
        if owner != uid:
            raise HTTPException(404, "Project not found")
    return pid


def _project_owner(pid: str) -> Optional[int]:
    """Return the owner user id for a project, or None if unclaimed."""
    with _OWNERSHIP_LOCK:
        return _load_ownership().get(pid)


class CompileRequest(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=64)
    code: str = Field(..., max_length=500_000)


class PublishRequest(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=64)
    code: str = Field(..., max_length=500_000)
    token: str = Field(..., min_length=1, max_length=120)


class BotCallRequest(BaseModel):
    fn_name: str = Field(..., min_length=1, max_length=64)
    args: list = Field(default_factory=list)


class SaveVersionRequest(BaseModel):
    code: str = Field(..., max_length=500_000)

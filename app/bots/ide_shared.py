"""
app/bots/ide_shared.py — Shared constants, models, and helpers for IDE routes.
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import HTTPException
from pydantic import BaseModel, Field


_BASE = Path(__file__).resolve().parent.parent.parent

_ID_RE = re.compile(r'^[a-zA-Z0-9_\-]+$')


def _validate_id(pid: str) -> str:
    if not _ID_RE.match(pid):
        raise HTTPException(400, "Invalid project_id")
    return pid


# ── Request models ─────────────────────────────────────────────────────────

class CompileRequest(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=64)
    code: str       = Field(..., max_length=500_000)


class PublishRequest(BaseModel):
    project_id: str = Field(..., min_length=1, max_length=64)
    code: str       = Field(..., max_length=500_000)
    token: str      = Field(..., min_length=1, max_length=120)


class BotCallRequest(BaseModel):
    fn_name: str = Field(..., min_length=1, max_length=64)
    args: list = Field(default_factory=list)


class SaveVersionRequest(BaseModel):
    code: str = Field(..., max_length=500_000)

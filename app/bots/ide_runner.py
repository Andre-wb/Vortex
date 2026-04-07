"""
app/bots/ide_runner.py — Gravitix bot process manager.

Manages compilation and lifecycle of Gravitix bots:
  compile(code) → parse errors via Gravitix binary
  publish(project_id, code, token) → start bot subprocess
  stop(project_id) → terminate bot process
  status(project_id) → running | stopped | error
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────
_BASE     = Path(__file__).resolve().parent.parent.parent   # project root
_BOTS_DIR = _BASE / "bots_workspace"
_GX_BIN   = _BASE / "Gravitix" / "target" / "release" / "gravitix"

_SAFE_PROJECT_ID = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')

# ── In-memory process registry ─────────────────────────────────────────────
class _BotProcess:
    def __init__(self, pid: int, proc: subprocess.Popen, project_id: str):
        self.pid        = pid
        self.proc       = proc
        self.project_id = project_id
        self.started_at = time.time()
        self.logs: List[str] = []

_procs: Dict[str, _BotProcess] = {}   # project_id → _BotProcess

# ── Helpers ────────────────────────────────────────────────────────────────
def _gx_available() -> bool:
    return _GX_BIN.exists() and os.access(_GX_BIN, os.X_OK)

def _parse_gx_errors(stderr: str) -> List[dict]:
    """Parse Gravitix compiler error output into structured dicts."""
    errors = []
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue
        # Basic parse: "error[E01] at line 5: ..."
        errors.append({"msg": line, "line": None, "col": None})
    return errors

def _script_path(project_id: str) -> Path:
    if not _SAFE_PROJECT_ID.match(project_id):
        raise ValueError(f"Invalid project_id: {project_id!r}")
    _BOTS_DIR.mkdir(parents=True, exist_ok=True)
    path = (_BOTS_DIR / f"{project_id}.grav").resolve()
    if not str(path).startswith(str(_BOTS_DIR.resolve()) + os.sep):
        raise ValueError(f"Path traversal detected for project_id: {project_id!r}")
    return path

# ── Public API ─────────────────────────────────────────────────────────────

async def compile_code(code: str, project_id: str) -> dict:
    """
    Write code to disk and invoke `gravitix check`.
    Returns {"ok": bool, "errors": [...], "warnings": [...]}.
    """
    if not _gx_available():
        return {
            "ok": False,
            "errors": [{"msg": (
                "Gravitix binary not found. "
                "Build it with: cd Gravitix && cargo build --release"
            ), "line": None}],
            "warnings": [],
        }

    path = _script_path(project_id)
    path.write_text(code, encoding="utf-8")

    try:
        proc = await asyncio.create_subprocess_exec(
            str(_GX_BIN), "check", str(path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
    except asyncio.TimeoutError:
        return {"ok": False, "errors": [{"msg": "Compilation timed out (>15s)", "line": None}], "warnings": []}
    except Exception as e:
        return {"ok": False, "errors": [{"msg": f"Compiler error: {e}", "line": None}], "warnings": []}

    if proc.returncode == 0:
        return {"ok": True, "errors": [], "warnings": []}

    errors = _parse_gx_errors(stderr.decode())
    if not errors:
        errors = [{"msg": stdout.decode().strip() or "Unknown compiler error", "line": None}]
    return {"ok": False, "errors": errors, "warnings": []}


async def publish_bot(project_id: str, code: str, token: str) -> dict:
    """
    Compile then start the bot process.
    Returns {"ok": bool, "pid": int|None, "error": str|None}.
    """
    # Stop previous instance first
    await stop_bot(project_id)

    # Write script
    path = _script_path(project_id)
    path.write_text(code, encoding="utf-8")

    if not _gx_available():
        return {"ok": False, "error": "Gravitix binary not found"}

    if not token:
        return {"ok": False, "error": "Bot token is required to publish"}

    # Token is passed via env var BOT_TOKEN — NOT as a CLI arg to keep it out of ps aux.
    env = {**os.environ, "BOT_TOKEN": token, "GX_PROJECT": project_id}

    try:
        proc = subprocess.Popen(
            [str(_GX_BIN), "run", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            cwd=str(_BASE),
        )
    except Exception as e:
        logger.exception("Failed to start bot %s", project_id)
        return {"ok": False, "error": str(e)}

    bp = _BotProcess(proc.pid, proc, project_id)
    _procs[project_id] = bp

    # Collect first few lines of output asynchronously
    asyncio.get_event_loop().run_in_executor(None, _collect_logs, project_id)

    logger.info("Bot %s started (pid=%d)", project_id, proc.pid)
    return {"ok": True, "pid": proc.pid, "error": None}


def _collect_logs(project_id: str):
    """Background thread: read stdout lines into log buffer (max 500 lines)."""
    bp = _procs.get(project_id)
    if not bp:
        return
    try:
        for line in bp.proc.stdout:
            bp.logs.append(line.rstrip())
            if len(bp.logs) > 500:
                bp.logs = bp.logs[-400:]
    except Exception as e:
        logger.debug("Bot log reader closed for project %s: %s", bp.project_id if hasattr(bp, 'project_id') else '?', e)


async def stop_bot(project_id: str) -> dict:
    bp = _procs.pop(project_id, None)
    if bp is None:
        return {"ok": True, "was_running": False}
    if bp.proc.poll() is None:
        bp.proc.terminate()
        try:
            bp.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            bp.proc.kill()
    logger.info("Bot %s stopped", project_id)
    return {"ok": True, "was_running": True}


def get_status(project_id: str) -> dict:
    bp = _procs.get(project_id)
    if bp is None:
        return {"status": "stopped", "pid": None, "uptime": None}
    if bp.proc.poll() is None:
        uptime = int(time.time() - bp.started_at)
        return {"status": "running", "pid": bp.pid, "uptime": uptime}
    rc = bp.proc.returncode
    _procs.pop(project_id, None)
    return {"status": "crashed", "pid": bp.pid, "exit_code": rc}


def get_logs(project_id: str, last_n: int = 100) -> List[str]:
    bp = _procs.get(project_id)
    if bp is None:
        return []
    return bp.logs[-last_n:]

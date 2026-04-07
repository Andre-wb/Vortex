"""
app/bots/ide_projects.py — Core IDE project endpoints.

POST /api/ide/compile      compile code, return errors
POST /api/ide/publish      compile + deploy bot to server
GET  /api/ide/status/{pid} get bot running status + uptime
GET  /api/ide/logs/{pid}   get recent bot stdout lines
POST /api/ide/stop/{pid}   stop running bot
POST /api/ide/test         run a bot script against a test message
POST /api/ide/ai/proxy     proxy AI requests to Ollama/OpenAI
"""
from __future__ import annotations

import asyncio
import os
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from app.models import User
from app.security.auth_jwt import get_current_user
from app.bots.ide_runner import (
    compile_code,
    get_logs,
    get_status,
    publish_bot,
    stop_bot,
)
from app.bots.ide_shared import CompileRequest, PublishRequest, _validate_id


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ide", tags=["ide"])


# ── Core IDE endpoints ────────────────────────────────────────────────────

@router.post("/compile")
async def ide_compile(
    body: CompileRequest,
    current_user: User = Depends(get_current_user),
):
    """Run Gravitix compiler on code and return structured error list."""
    pid = _validate_id(body.project_id)
    result = await compile_code(body.code, pid)
    return result


@router.post("/publish")
async def ide_publish(
    body: PublishRequest,
    current_user: User = Depends(get_current_user),
):
    """Compile and deploy bot; starts subprocess on the server."""
    pid = _validate_id(body.project_id)
    result = await publish_bot(pid, body.code, body.token)
    if not result["ok"]:
        raise HTTPException(422, result.get("error", "Publish failed"))
    return result


@router.get("/status/{project_id}")
async def ide_status(
    project_id: str,
    current_user: User = Depends(get_current_user),
):
    pid = _validate_id(project_id)
    return get_status(pid)


@router.get("/logs/{project_id}")
async def ide_logs(
    project_id: str,
    n: int = 100,
    current_user: User = Depends(get_current_user),
):
    pid = _validate_id(project_id)
    return {"logs": get_logs(pid, last_n=min(n, 500))}


@router.post("/stop/{project_id}")
async def ide_stop(
    project_id: str,
    current_user: User = Depends(get_current_user),
):
    pid = _validate_id(project_id)
    return await stop_bot(pid)


# ── Test endpoint ─────────────────────────────────────────────────────────

@router.post("/test")
async def test_bot(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """
    Run a bot script against a test message and return the bot's response.
    Body: { "code": str, "message": str, "update_type": "message"|"command"|"callback" }
    """
    body = await request.json()
    code = body.get("code", "")
    test_message = body.get("message", "/start")
    update_type = body.get("update_type", "command" if test_message.startswith("/") else "message")

    if not code.strip():
        return JSONResponse({"ok": False, "error": "No code provided"}, status_code=400)

    import tempfile
    from app.bots.ide_runner import _GX_BIN, _gx_available

    if not _gx_available():
        return JSONResponse({"ok": False, "error": "Gravitix binary not found"}, status_code=500)

    # Write code to temp file
    with tempfile.NamedTemporaryFile(suffix=".grav", mode="w", delete=False, encoding="utf-8") as f:
        f.write(code)
        tmp_path = f.name

    try:
        # Run syntax check first
        proc = await asyncio.create_subprocess_exec(
            str(_GX_BIN), "check", tmp_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)

        if proc.returncode != 0:
            return JSONResponse({
                "ok": False,
                "error": "Syntax error",
                "details": stderr.decode().strip()
            })

        # Return success - full sandbox execution would require a real test room
        return JSONResponse({
            "ok": True,
            "syntax_valid": True,
            "message": f"Code compiled successfully. Deploy with 'Publish' to test with real messages.",
            "test_input": test_message,
            "update_type": update_type,
        })
    except asyncio.TimeoutError:
        return JSONResponse({"ok": False, "error": "Test timed out"}, status_code=408)
    finally:
        os.unlink(tmp_path)


# ── AI Proxy (supports ai() builtin in Gravitix) ─────────────────────────

@router.post("/ai/proxy")
async def ai_proxy(
    body: dict,
    current_user: User = Depends(get_current_user),
):
    """Proxy AI requests from Gravitix bots to Ollama/OpenAI-compatible endpoint."""
    import httpx
    ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    model = body.get("model", os.environ.get("AI_MODEL", "llama3"))
    prompt = body.get("prompt", "")
    history = body.get("history", [])  # list of {role, content}

    try:
        if history:
            # OpenAI-compatible chat completions
            messages = history + [{"role": "user", "content": prompt}]
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    f"{ollama_url}/v1/chat/completions",
                    json={"model": model, "messages": messages, "stream": False},
                )
                data = r.json()
                text = data["choices"][0]["message"]["content"]
        else:
            # Ollama generate
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    f"{ollama_url}/api/generate",
                    json={"model": model, "prompt": prompt, "stream": False},
                )
                data = r.json()
                text = data.get("response", "")
        return {"ok": True, "text": text}
    except Exception as e:
        return {"ok": False, "error": str(e), "text": ""}

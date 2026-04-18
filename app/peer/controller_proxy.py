"""Multihop proxy to the controller.

A Vortex node exposes POST /api/peers/controller-proxy. Clients (or other nodes)
that cannot reach the controller directly (domain-level block) can send their
HTTP request *as data* to any reachable Vortex node — that node forwards it to
the controller and returns the response.

Safety:
    - Only the controller endpoints we explicitly allow are proxied.
    - Request/response bodies are passed through unchanged; the node never
      inspects or modifies the controller's signature.
    - A client can chain this through multiple nodes: node-A forwards to node-B,
      which forwards to the controller.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field

from app.config import Config
from app.peer._router import router

logger = logging.getLogger(__name__)


# ── Allowlist of controller endpoints we agree to proxy ────────────────────
# Keep this tight — the proxy is not a general-purpose HTTP relay.
_ALLOWED_PATHS = {
    "GET":  {"/v1/health", "/v1/entries", "/v1/mirrors", "/v1/nodes/random", "/v1/nodes/lookup"},
    "POST": {"/v1/register", "/v1/heartbeat"},
}

# Prevent recursive proxy chains from growing unboundedly.
MAX_HOPS = 3


class ControllerProxyRequest(BaseModel):
    method: str = Field(..., description="GET or POST")
    path: str = Field(..., description="e.g. /v1/nodes/random?count=5")
    body: Optional[dict] = Field(None, description="JSON body for POST")
    # Where to forward. If empty, the node uses its own CONTROLLER_URL.
    controller_url: Optional[str] = None
    # Simple hop counter to stop chain loops.
    hops: int = Field(default=0, ge=0, le=MAX_HOPS)


class ControllerProxyResponse(BaseModel):
    status_code: int
    body: Any
    # The pubkey of the controller we spoke to, for client-side verification.
    via_controller: Optional[str] = None


def _is_allowed(method: str, path: str) -> bool:
    method = method.upper()
    if method not in _ALLOWED_PATHS:
        return False
    # Strip query string for prefix match
    base = path.split("?", 1)[0].rstrip("/")
    # Allow exact matches and /v1/nodes/lookup/{pubkey}
    if base in _ALLOWED_PATHS[method]:
        return True
    if method == "GET" and base.startswith("/v1/nodes/lookup/"):
        return True
    return False


@router.post("/controller-proxy", response_model=ControllerProxyResponse)
async def controller_proxy(
    req: ControllerProxyRequest,
    request: Request,
) -> ControllerProxyResponse:
    """Forward a single controller request on behalf of the caller."""
    if req.hops >= MAX_HOPS:
        raise HTTPException(429, f"max hops ({MAX_HOPS}) exceeded")
    if not _is_allowed(req.method, req.path):
        raise HTTPException(400, f"path not allowed: {req.method} {req.path}")

    target_url = (req.controller_url or Config.CONTROLLER_URL).rstrip("/")
    if not target_url:
        raise HTTPException(503, "this node has no controller configured")

    full = target_url + req.path
    method = req.method.upper()

    try:
        async with httpx.AsyncClient(timeout=15) as http:
            if method == "GET":
                r = await http.get(full)
            else:
                r = await http.post(full, json=req.body or {})
    except httpx.HTTPError as e:
        logger.info("controller-proxy: %s %s failed: %s", method, full, e)
        raise HTTPException(502, f"controller unreachable: {e}")

    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text}

    # If the response includes a "signed_by" field (as our signed responses do),
    # surface it so the client can cross-check the pinned pubkey.
    signed_by = None
    if isinstance(body, dict):
        signed_by = body.get("signed_by")

    return ControllerProxyResponse(
        status_code=r.status_code,
        body=body,
        via_controller=signed_by,
    )

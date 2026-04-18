"""Pydantic models for the controller API."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class RegistrationPayload(BaseModel):
    """Data the node signs. Must be stable across client/server."""
    pubkey: str = Field(..., description="hex-encoded ed25519 public key")
    endpoints: list[str] = Field(
        ..., description="list of reachable URLs (wss://, https://, .onion, etc.)"
    )
    metadata: dict = Field(default_factory=dict)
    timestamp: int = Field(..., description="unix seconds, rejected if stale")


class RegistrationRequest(BaseModel):
    payload: RegistrationPayload
    signature: str = Field(..., description="hex ed25519 signature over canonical JSON of payload")


class HeartbeatPayload(BaseModel):
    pubkey: str
    timestamp: int


class HeartbeatRequest(BaseModel):
    payload: HeartbeatPayload
    signature: str


class NodeInfo(BaseModel):
    pubkey: str
    endpoints: list[str]
    metadata: dict
    last_seen: int


class SignedResponse(BaseModel):
    """Generic envelope. Clients verify `signature` with pinned controller pubkey."""
    payload: dict
    signature: str
    signed_by: str


class HealthResponse(BaseModel):
    status: str
    version: str
    pubkey: str
    stats: dict


class RegisterAck(BaseModel):
    ok: bool
    approved: bool
    message: Optional[str] = None

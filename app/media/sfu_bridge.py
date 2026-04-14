"""
app/media/sfu_bridge.py -- Abstract SFU interface with pluggable backends.

Supported modes (SFU_MODE env):
  - builtin     -- existing aiortc-based SFU (default)
  - mediasoup   -- external mediasoup server via HTTP API
  - janus       -- external Janus Gateway via HTTP API

Configuration:
  SFU_MODE=builtin|mediasoup|janus
  SFU_URL=http://mediasoup-host:3000   (for external SFUs)
  SFU_API_KEY=secret                    (optional auth for external SFU)
"""
from __future__ import annotations

import abc
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SFU_MODE: str = os.getenv("SFU_MODE", "builtin")  # builtin | mediasoup | janus
SFU_URL: str = os.getenv("SFU_URL", "")
SFU_API_KEY: str = os.getenv("SFU_API_KEY", "")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SFUParticipantInfo:
    user_id: int
    username: str
    display_name: str = ""


@dataclass
class SFURoomInfo:
    room_id: str
    participants: list[SFUParticipantInfo] = field(default_factory=list)
    created: bool = False


# ---------------------------------------------------------------------------
# Abstract SFU bridge
# ---------------------------------------------------------------------------

class SFUBridge(abc.ABC):
    """Abstract interface for SFU operations."""

    name: str = "base"

    @abc.abstractmethod
    async def create_room(self, room_id: str, **kwargs) -> SFURoomInfo:
        """Create a media room. Returns room info."""

    @abc.abstractmethod
    async def join_room(
        self,
        room_id: str,
        user_id: int,
        username: str,
        sdp_offer: Optional[str] = None,
        **kwargs,
    ) -> dict:
        """
        Join a room. Returns a dict with at least:
          {"sdp_answer": str, "participants": list[dict]}
        """

    @abc.abstractmethod
    async def leave_room(self, room_id: str, user_id: int) -> bool:
        """Leave a room. Returns True on success."""

    @abc.abstractmethod
    async def get_participants(self, room_id: str) -> list[SFUParticipantInfo]:
        """Return current participants of a room."""

    async def close_room(self, room_id: str) -> bool:
        """Close/destroy a room. Default: no-op."""
        return True

    async def is_available(self) -> bool:
        """Check if the SFU backend is reachable."""
        return False


# ---------------------------------------------------------------------------
# Builtin SFU (delegates to existing app/chats/sfu.py with aiortc)
# ---------------------------------------------------------------------------

class BuiltinSFU(SFUBridge):
    """
    Uses the existing aiortc-based SFU in app/chats/sfu.py.
    This is a thin adapter that bridges the abstract interface to the
    existing SFURoom class.
    """

    name = "builtin"

    async def is_available(self) -> bool:
        try:
            from app.chats.sfu import is_sfu_available
            return is_sfu_available()
        except ImportError:
            return False

    async def create_room(self, room_id: str, **kwargs) -> SFURoomInfo:
        from app.chats.sfu import get_or_create_sfu_room
        # Room is lazily created on join, but we can pre-create it
        # The second arg is numeric room_id used for access control
        numeric_room = kwargs.get("numeric_room_id", 0)
        sfu_room = get_or_create_sfu_room(room_id, numeric_room)
        return SFURoomInfo(room_id=room_id, created=True)

    async def join_room(self, room_id, user_id, username, sdp_offer=None, **kwargs):
        from app.chats.sfu import get_or_create_sfu_room, _sfu_rooms
        sfu_room = _sfu_rooms.get(room_id)
        if not sfu_room:
            numeric_room = kwargs.get("numeric_room_id", 0)
            sfu_room = get_or_create_sfu_room(room_id, numeric_room)

        # The builtin SFU expects a User object; build a minimal one
        user_obj = kwargs.get("user_obj")
        if user_obj is None:
            raise ValueError("BuiltinSFU.join_room requires user_obj in kwargs")

        if not sdp_offer:
            raise ValueError("BuiltinSFU.join_room requires sdp_offer")

        answer_sdp, participants = await sfu_room.join(user_obj, sdp_offer)
        return {"sdp_answer": answer_sdp, "participants": participants}

    async def leave_room(self, room_id, user_id):
        from app.chats.sfu import _sfu_rooms
        sfu_room = _sfu_rooms.get(room_id)
        if sfu_room:
            await sfu_room.leave(user_id)
            return True
        return False

    async def get_participants(self, room_id):
        from app.chats.sfu import _sfu_rooms
        sfu_room = _sfu_rooms.get(room_id)
        if not sfu_room:
            return []
        return [
            SFUParticipantInfo(
                user_id=p.user_id,
                username=p.username,
                display_name=p.display_name,
            )
            for p in sfu_room.participants.values()
        ]

    async def close_room(self, room_id):
        from app.chats.sfu import _sfu_rooms
        sfu_room = _sfu_rooms.get(room_id)
        if sfu_room:
            await sfu_room.close()
            return True
        return False


# ---------------------------------------------------------------------------
# Mediasoup bridge (HTTP API)
# ---------------------------------------------------------------------------

class MediasoupBridge(SFUBridge):
    """
    Connect to an external mediasoup server via its HTTP API.

    Expected mediasoup HTTP API:
      POST /rooms                       -- create room
      POST /rooms/{id}/join             -- join (SDP offer -> answer)
      POST /rooms/{id}/leave            -- leave
      GET  /rooms/{id}/participants     -- list participants
      DELETE /rooms/{id}                -- close room
    """

    name = "mediasoup"

    def __init__(self, url: Optional[str] = None, api_key: Optional[str] = None):
        self.url = (url or SFU_URL).rstrip("/")
        self.api_key = api_key or SFU_API_KEY

    def _headers(self) -> dict:
        h: dict = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    async def is_available(self) -> bool:
        if not self.url:
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                r = await c.get(f"{self.url}/health", headers=self._headers())
                return r.status_code == 200
        except Exception:
            return False

    async def create_room(self, room_id, **kwargs):
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.post(
                f"{self.url}/rooms",
                json={"roomId": room_id},
                headers=self._headers(),
            )
            r.raise_for_status()
        return SFURoomInfo(room_id=room_id, created=True)

    async def join_room(self, room_id, user_id, username, sdp_offer=None, **kwargs):
        payload = {
            "userId": user_id,
            "username": username,
            "displayName": kwargs.get("display_name", username),
        }
        if sdp_offer:
            payload["sdpOffer"] = sdp_offer

        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.post(
                f"{self.url}/rooms/{room_id}/join",
                json=payload,
                headers=self._headers(),
            )
            r.raise_for_status()
            data = r.json()

        return {
            "sdp_answer": data.get("sdpAnswer", ""),
            "participants": data.get("participants", []),
        }

    async def leave_room(self, room_id, user_id):
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.post(
                    f"{self.url}/rooms/{room_id}/leave",
                    json={"userId": user_id},
                    headers=self._headers(),
                )
                return r.status_code == 200
        except Exception as e:
            logger.warning("Mediasoup leave_room error: %s", e)
            return False

    async def get_participants(self, room_id):
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                r = await c.get(
                    f"{self.url}/rooms/{room_id}/participants",
                    headers=self._headers(),
                )
                r.raise_for_status()
                items = r.json().get("participants", [])
                return [
                    SFUParticipantInfo(
                        user_id=p.get("userId", 0),
                        username=p.get("username", ""),
                        display_name=p.get("displayName", ""),
                    )
                    for p in items
                ]
        except Exception as e:
            logger.warning("Mediasoup get_participants error: %s", e)
            return []

    async def close_room(self, room_id):
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.delete(
                    f"{self.url}/rooms/{room_id}",
                    headers=self._headers(),
                )
                return r.status_code in (200, 204)
        except Exception as e:
            logger.warning("Mediasoup close_room error: %s", e)
            return False


# ---------------------------------------------------------------------------
# Janus bridge (HTTP API)
# ---------------------------------------------------------------------------

class JanusBridge(SFUBridge):
    """
    Connect to an external Janus Gateway via its REST API.

    Uses the Janus VideoRoom plugin for SFU functionality.
    Janus HTTP transport: POST /janus with JSON transactions.
    """

    name = "janus"

    def __init__(self, url: Optional[str] = None, api_key: Optional[str] = None):
        self.url = (url or SFU_URL).rstrip("/")
        self.api_key = api_key or SFU_API_KEY
        self._session_id: Optional[int] = None
        self._handle_ids: dict[str, int] = {}  # room_id -> plugin handle id

    async def _janus_request(self, body: dict, timeout: float = 10.0) -> dict:
        """Send a request to Janus REST API."""
        if self.api_key:
            body["apisecret"] = self.api_key
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.post(f"{self.url}/janus", json=body)
            r.raise_for_status()
            return r.json()

    async def _janus_session_request(self, body: dict, timeout: float = 10.0) -> dict:
        """Send a request to an existing Janus session."""
        if not self._session_id:
            await self._create_session()
        if self.api_key:
            body["apisecret"] = self.api_key
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.post(f"{self.url}/janus/{self._session_id}", json=body)
            r.raise_for_status()
            return r.json()

    async def _create_session(self) -> None:
        data = await self._janus_request({"janus": "create", "transaction": "create_session"})
        self._session_id = data.get("data", {}).get("id")

    async def is_available(self) -> bool:
        if not self.url:
            return False
        try:
            data = await self._janus_request({"janus": "info", "transaction": "info"})
            return data.get("janus") == "server_info"
        except Exception:
            return False

    async def create_room(self, room_id, **kwargs):
        if not self._session_id:
            await self._create_session()

        # Attach to videoroom plugin
        attach_data = await self._janus_session_request({
            "janus": "attach",
            "plugin": "janus.plugin.videoroom",
            "transaction": f"attach_{room_id}",
        })
        handle_id = attach_data.get("data", {}).get("id")
        if handle_id:
            self._handle_ids[room_id] = handle_id

        # Create room via plugin message
        if handle_id:
            async with httpx.AsyncClient(timeout=10.0) as c:
                body: dict = {
                    "janus": "message",
                    "transaction": f"create_room_{room_id}",
                    "body": {
                        "request": "create",
                        "room": room_id,
                        "publishers": 50,
                        "bitrate": 512000,
                        "videocodec": "vp8,h264",
                        "audiocodec": "opus",
                    },
                }
                if self.api_key:
                    body["apisecret"] = self.api_key
                r = await c.post(
                    f"{self.url}/janus/{self._session_id}/{handle_id}",
                    json=body,
                )
                r.raise_for_status()

        return SFURoomInfo(room_id=room_id, created=True)

    async def join_room(self, room_id, user_id, username, sdp_offer=None, **kwargs):
        handle_id = self._handle_ids.get(room_id)
        if not handle_id or not self._session_id:
            # Need to attach first
            await self.create_room(room_id, **kwargs)
            handle_id = self._handle_ids.get(room_id)
            if not handle_id:
                raise RuntimeError("Failed to get Janus handle for room")

        body: dict = {
            "janus": "message",
            "transaction": f"join_{room_id}_{user_id}",
            "body": {
                "request": "join",
                "ptype": "publisher",
                "room": room_id,
                "display": username,
            },
        }
        if sdp_offer:
            body["jsep"] = {"type": "offer", "sdp": sdp_offer}
        if self.api_key:
            body["apisecret"] = self.api_key

        async with httpx.AsyncClient(timeout=15.0) as c:
            r = await c.post(
                f"{self.url}/janus/{self._session_id}/{handle_id}",
                json=body,
            )
            r.raise_for_status()
            data = r.json()

        jsep = data.get("jsep", {})
        plugindata = data.get("plugindata", {}).get("data", {})
        participants = plugindata.get("publishers", [])

        return {
            "sdp_answer": jsep.get("sdp", ""),
            "participants": [
                {"user_id": p.get("id"), "username": p.get("display", "")}
                for p in participants
            ],
        }

    async def leave_room(self, room_id, user_id):
        handle_id = self._handle_ids.get(room_id)
        if not handle_id or not self._session_id:
            return False
        try:
            body: dict = {
                "janus": "message",
                "transaction": f"leave_{room_id}_{user_id}",
                "body": {"request": "leave"},
            }
            if self.api_key:
                body["apisecret"] = self.api_key
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.post(
                    f"{self.url}/janus/{self._session_id}/{handle_id}",
                    json=body,
                )
                return r.status_code == 200
        except Exception as e:
            logger.warning("Janus leave_room error: %s", e)
            return False

    async def get_participants(self, room_id):
        handle_id = self._handle_ids.get(room_id)
        if not handle_id or not self._session_id:
            return []
        try:
            body: dict = {
                "janus": "message",
                "transaction": f"list_{room_id}",
                "body": {"request": "listparticipants", "room": room_id},
            }
            if self.api_key:
                body["apisecret"] = self.api_key
            async with httpx.AsyncClient(timeout=5.0) as c:
                r = await c.post(
                    f"{self.url}/janus/{self._session_id}/{handle_id}",
                    json=body,
                )
                r.raise_for_status()
                data = r.json()
                items = data.get("plugindata", {}).get("data", {}).get("participants", [])
                return [
                    SFUParticipantInfo(
                        user_id=p.get("id", 0),
                        username=p.get("display", ""),
                        display_name=p.get("display", ""),
                    )
                    for p in items
                ]
        except Exception as e:
            logger.warning("Janus get_participants error: %s", e)
            return []


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_cached_bridge: Optional[SFUBridge] = None


def get_sfu_bridge() -> SFUBridge:
    """Return the configured SFU bridge (cached singleton)."""
    global _cached_bridge
    if _cached_bridge is not None:
        return _cached_bridge

    mode = SFU_MODE.lower()
    if mode == "mediasoup":
        _cached_bridge = MediasoupBridge()
        logger.info("SFU bridge: mediasoup (%s)", SFU_URL)
    elif mode == "janus":
        _cached_bridge = JanusBridge()
        logger.info("SFU bridge: Janus (%s)", SFU_URL)
    else:
        _cached_bridge = BuiltinSFU()
        logger.info("SFU bridge: builtin (aiortc)")
    return _cached_bridge

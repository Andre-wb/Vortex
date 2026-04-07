"""
app/chats/voice.py -- Persistent voice channels backend (Discord-style).

Voice channels are Room objects with is_voice=True. Users freely join/leave
voice -- there is no "calling" concept. Voice state is in-memory only;
a server restart empties all voice channels (expected behavior).

Architecture:
  - _voice_participants: dict[room_id, dict[user_id, participant_info]]
    Tracks who is currently in each voice channel.
  - REST endpoints for join/leave/mute/participants.
  - Enhanced signal WebSocket at /ws/voice-signal/{room_id} for mesh
    WebRTC signaling among voice channel participants.
  - Auto-leave on signal WS disconnect.
  - Broadcasts voice_update to the chat WS so the UI can show who is in voice.
"""
from __future__ import annotations

import json as _json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.models_rooms import Room, RoomMember
from app.peer.connection_manager import manager
from app.security.auth_jwt import get_current_user, get_user_ws

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/voice", tags=["voice"])
# Separate router for WebSocket (no prefix, so WS path is /ws/voice-signal/{room_id})
ws_router = APIRouter(tags=["voice"])


# ==============================================================================
# In-memory voice state
# ==============================================================================

# room_id -> {user_id -> {username, display_name, avatar_emoji, avatar_url,
#                          joined_at, is_muted, is_video}}
_voice_participants: dict[int, dict[int, dict]] = {}

# room_id -> {user_id -> WebSocket}   (voice-signal WS connections)
_voice_signal_rooms: dict[int, dict[int, WebSocket]] = {}


def _make_participant(user: User, is_muted: bool = False, is_video: bool = False) -> dict:
    """Build a participant dict from a User object."""
    return {
        "user_id":      user.id,
        "username":     user.username,
        "display_name": user.display_name or user.username,
        "avatar_emoji": user.avatar_emoji or "\U0001f464",
        "avatar_url":   user.avatar_url,
        "joined_at":    datetime.now(timezone.utc).isoformat(),
        "is_muted":     is_muted,
        "is_video":     is_video,
    }


def get_voice_participants(room_id: int) -> list[dict]:
    """Return current voice participants for a room (used by _room_dict)."""
    return list(_voice_participants.get(room_id, {}).values())


def get_voice_participant_count(room_id: int) -> int:
    """Return how many users are currently in a voice channel."""
    return len(_voice_participants.get(room_id, {}))


def _require_voice_room(room_id: int, db: Session) -> Room:
    """Fetch room and verify it is a voice channel."""
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(404, "Room not found")
    if not getattr(room, "is_voice", False):
        raise HTTPException(400, "This room is not a voice channel")
    return room


def _require_room_member(room_id: int, user_id: int, db: Session) -> RoomMember:
    """Verify user is a non-banned member of the room."""
    m = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user_id,
        RoomMember.is_banned == False,
    ).first()
    if not m:
        raise HTTPException(403, "Not a member of this room")
    return m


async def _broadcast_voice_update(
    room_id: int,
    action: str,
    user_info: dict,
) -> None:
    """
    Broadcast a voice_update event to the chat WS for the room.
    This lets the sidebar/room list show who is in voice.
    """
    participants = get_voice_participants(room_id)
    await manager.broadcast_to_room(room_id, {
        "type":         "voice_update",
        "room_id":      room_id,
        "action":       action,   # "join" | "leave" | "mute"
        "user":         user_info,
        "participants": participants,
    })

    # Also send via global notification WS to members not connected to the room
    # so their room list can update voice participant counts
    for uid in list(manager._global_ws.keys()):
        await manager.notify_user(uid, {
            "type":                   "voice_state",
            "room_id":                room_id,
            "action":                 action,
            "voice_participant_count": len(participants),
            "participants":           participants,
        })


async def _remove_participant(room_id: int, user_id: int) -> Optional[dict]:
    """
    Remove a user from voice participants. Returns the removed participant
    dict, or None if user was not in the channel.
    """
    room_participants = _voice_participants.get(room_id)
    if not room_participants:
        return None
    removed = room_participants.pop(user_id, None)
    if not room_participants:
        _voice_participants.pop(room_id, None)
    return removed


# ==============================================================================
# REST: Join voice channel
# ==============================================================================

@router.post("/{room_id}/join")
async def voice_join(
    room_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Join a voice channel. Adds the user to in-memory voice participants
    and broadcasts voice_join to the room.
    Returns the current participants list.
    """
    room = _require_voice_room(room_id, db)
    _require_room_member(room_id, u.id, db)

    # Already in voice? Return current state
    if room_id in _voice_participants and u.id in _voice_participants[room_id]:
        return {
            "joined":       True,
            "already_in":   True,
            "participants": get_voice_participants(room_id),
        }

    participant = _make_participant(u)
    _voice_participants.setdefault(room_id, {})[u.id] = participant

    logger.info(f"Voice join: {u.username}({u.id}) -> room {room_id}")

    await _broadcast_voice_update(room_id, "join", participant)

    return {
        "joined":       True,
        "already_in":   False,
        "participants": get_voice_participants(room_id),
    }


# ==============================================================================
# REST: Leave voice channel
# ==============================================================================

@router.post("/{room_id}/leave")
async def voice_leave(
    room_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Leave a voice channel. Removes user from participants and broadcasts
    voice_leave to remaining participants.
    """
    _require_voice_room(room_id, db)

    removed = await _remove_participant(room_id, u.id)
    if not removed:
        raise HTTPException(400, "Not currently in this voice channel")

    logger.info(f"Voice leave: {u.username}({u.id}) <- room {room_id}")

    # Also disconnect signal WS if still connected
    sig_rooms = _voice_signal_rooms.get(room_id, {})
    ws = sig_rooms.pop(u.id, None)
    if ws:
        try:
            await ws.close(code=1000)
        except Exception as e:
            logger.debug("Voice WS close error for user %s room %s: %s", u.id, room_id, e)
    if not sig_rooms and room_id in _voice_signal_rooms:
        _voice_signal_rooms.pop(room_id, None)

    await _broadcast_voice_update(room_id, "leave", removed)

    return {
        "left":         True,
        "participants": get_voice_participants(room_id),
    }

@router.get("/{room_id}/participants")
async def voice_participants(
    room_id: int,
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return current voice participants for a voice channel."""
    _require_voice_room(room_id, db)
    _require_room_member(room_id, u.id, db)

    return {
        "room_id":      room_id,
        "participants": get_voice_participants(room_id),
    }


# ==============================================================================
# REST: Mute / unmute / toggle video
# ==============================================================================

# In-memory: room_id -> list of recording chunks metadata
_voice_recordings: dict[int, dict] = {}
# In-memory: stage mode state
_stage_speakers: dict[int, set[int]] = {}  # room_id -> set of speaker user_ids


class VoiceMuteRequest(BaseModel):
    is_muted: Optional[bool] = None   # None = toggle
    is_video: Optional[bool] = None   # None = no change


@router.post("/{room_id}/mute")
async def voice_mute(
    room_id: int,
    body: VoiceMuteRequest = VoiceMuteRequest(),
    u:  User    = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Toggle mute/video state in voice channel. Broadcasts voice_mute
    to all participants.
    """
    _require_voice_room(room_id, db)

    room_participants = _voice_participants.get(room_id, {})
    participant = room_participants.get(u.id)
    if not participant:
        raise HTTPException(400, "Not currently in this voice channel")

    # Update mute state
    if body.is_muted is not None:
        participant["is_muted"] = body.is_muted
    else:
        participant["is_muted"] = not participant["is_muted"]

    # Update video state
    if body.is_video is not None:
        participant["is_video"] = body.is_video

    logger.info(
        f"Voice mute: {u.username}({u.id}) in room {room_id} "
        f"muted={participant['is_muted']} video={participant['is_video']}"
    )

    await _broadcast_voice_update(room_id, "mute", participant)

    # Also notify via voice-signal WS so WebRTC peers can update UI
    sig_rooms = _voice_signal_rooms.get(room_id, {})
    mute_msg = _json.dumps({
        "type":     "voice_mute",
        "from":     u.id,
        "username": u.username,
        "is_muted": participant["is_muted"],
        "is_video": participant["is_video"],
    })
    for uid, ws in list(sig_rooms.items()):
        if uid != u.id:
            try:
                await ws.send_text(mute_msg)
            except Exception as e:
                logger.debug("Voice mute broadcast: dead WS for user %s room %s: %s", uid, room_id, e)
                sig_rooms.pop(uid, None)

    return {
        "is_muted": participant["is_muted"],
        "is_video": participant["is_video"],
    }


# ==============================================================================
# SFU Configuration (Selective Forwarding Unit)
# ==============================================================================

@router.get("/{room_id}/sfu-config")
async def sfu_config(room_id: int, u: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    """
    Return SFU/mesh topology recommendation based on participant count.

    Mesh: <=6 participants (each peer connects to every other)
    SFU:  >6 participants (peers send to SFU, SFU forwards selectively)
    """
    _require_voice_room(room_id, db)
    count = get_voice_participant_count(room_id)
    # Mesh topology for small groups, SFU for larger
    topology = "mesh" if count <= 6 else "sfu"
    return {
        "topology": topology,
        "participant_count": count,
        "max_video_streams": 6 if topology == "mesh" else 50,
        "sfu_url": None,  # External SFU URL (Janus/mediasoup) — configure via SFU_URL env
        "simulcast": topology == "sfu",  # Enable simulcast for SFU mode
        "audio_config": {
            "noise_suppression": True,
            "echo_cancellation": True,
            "auto_gain_control": True,
            "sample_rate": 48000,
        },
        "video_config": {
            "background_blur": True,
            "virtual_background": True,
            "picture_in_picture": True,
            "simulcast_layers": [
                {"rid": "high", "maxBitrate": 2500000, "maxFramerate": 30},
                {"rid": "mid", "maxBitrate": 500000, "maxFramerate": 15},
                {"rid": "low", "maxBitrate": 100000, "maxFramerate": 7},
            ] if topology == "sfu" else [],
        },
    }


# ==============================================================================
# Recording (E2E encrypted call recording)
# ==============================================================================

@router.post("/{room_id}/recording/start")
async def start_recording(room_id: int, u: User = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    """
    Start recording the voice channel.
    Recording is done client-side (MediaRecorder API) and uploaded encrypted.
    Server only tracks recording state.
    """
    _require_voice_room(room_id, db)
    member = _require_room_member(room_id, u.id, db)
    if member.role not in ("owner", "admin"):
        raise HTTPException(403, "Only admins can start recording")

    if room_id in _voice_recordings:
        return {"recording": True, "already_started": True}

    _voice_recordings[room_id] = {
        "started_by": u.id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "participants": list(_voice_participants.get(room_id, {}).keys()),
    }

    # Notify all participants that recording started
    await _broadcast_voice_update(room_id, "recording_start", {
        "started_by": u.username,
        "user_id": u.id,
    })

    return {"recording": True, "started_at": _voice_recordings[room_id]["started_at"]}


@router.post("/{room_id}/recording/stop")
async def stop_recording(room_id: int, u: User = Depends(get_current_user),
                         db: Session = Depends(get_db)):
    """Stop recording. Clients should upload their encrypted recording chunks."""
    _require_voice_room(room_id, db)

    rec = _voice_recordings.pop(room_id, None)
    if not rec:
        raise HTTPException(400, "No active recording")

    await _broadcast_voice_update(room_id, "recording_stop", {
        "stopped_by": u.username,
        "user_id": u.id,
    })

    return {"recording": False, "duration_since_start": rec["started_at"]}


@router.get("/{room_id}/recording/status")
async def recording_status(room_id: int, u: User = Depends(get_current_user),
                           db: Session = Depends(get_db)):
    """Check if recording is active."""
    rec = _voice_recordings.get(room_id)
    return {
        "recording": rec is not None,
        "started_at": rec["started_at"] if rec else None,
        "started_by": rec["started_by"] if rec else None,
    }


# ==============================================================================
# Stage Mode (one-to-many: speakers + listeners)
# ==============================================================================

@router.post("/{room_id}/stage/enable")
async def enable_stage(room_id: int, u: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    """
    Enable stage mode. Only designated speakers can unmute.
    Everyone else is a listener (muted, can raise hand to request speaking).
    Used for: webinars, podcasts, AMAs, presentations.
    """
    _require_voice_room(room_id, db)
    member = _require_room_member(room_id, u.id, db)
    if member.role not in ("owner", "admin"):
        raise HTTPException(403, "Only admins can enable stage mode")

    _stage_speakers[room_id] = {u.id}  # Creator is first speaker

    await _broadcast_voice_update(room_id, "stage_enabled", {
        "enabled_by": u.username,
        "speakers": [u.id],
    })

    return {"stage_mode": True, "speakers": [u.id]}


@router.post("/{room_id}/stage/disable")
async def disable_stage(room_id: int, u: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    """Disable stage mode — everyone can speak again."""
    _require_voice_room(room_id, db)
    _stage_speakers.pop(room_id, None)

    await _broadcast_voice_update(room_id, "stage_disabled", {
        "disabled_by": u.username,
    })

    return {"stage_mode": False}


@router.post("/{room_id}/stage/add-speaker/{target_id}")
async def add_speaker(room_id: int, target_id: int, u: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    """Promote a listener to speaker in stage mode."""
    _require_voice_room(room_id, db)
    member = _require_room_member(room_id, u.id, db)
    if member.role not in ("owner", "admin"):
        raise HTTPException(403, "Only admins can add speakers")

    speakers = _stage_speakers.get(room_id)
    if speakers is None:
        raise HTTPException(400, "Stage mode not enabled")

    speakers.add(target_id)

    await _broadcast_voice_update(room_id, "speaker_added", {
        "user_id": target_id,
        "added_by": u.username,
    })

    return {"ok": True, "speakers": list(speakers)}


@router.post("/{room_id}/stage/remove-speaker/{target_id}")
async def remove_speaker(room_id: int, target_id: int, u: User = Depends(get_current_user),
                         db: Session = Depends(get_db)):
    """Demote a speaker to listener in stage mode."""
    _require_voice_room(room_id, db)
    member = _require_room_member(room_id, u.id, db)
    if member.role not in ("owner", "admin"):
        raise HTTPException(403, "Only admins can remove speakers")

    speakers = _stage_speakers.get(room_id)
    if speakers is None:
        raise HTTPException(400, "Stage mode not enabled")

    speakers.discard(target_id)

    await _broadcast_voice_update(room_id, "speaker_removed", {
        "user_id": target_id,
        "removed_by": u.username,
    })

    return {"ok": True, "speakers": list(speakers)}


@router.post("/{room_id}/stage/raise-hand")
async def raise_hand(room_id: int, u: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    """Listener requests to become a speaker (raise hand)."""
    _require_voice_room(room_id, db)

    speakers = _stage_speakers.get(room_id)
    if speakers is None:
        raise HTTPException(400, "Stage mode not enabled")

    await _broadcast_voice_update(room_id, "hand_raised", {
        "user_id": u.id,
        "username": u.username,
        "display_name": u.display_name or u.username,
    })

    return {"ok": True, "hand_raised": True}


@router.get("/{room_id}/stage/status")
async def stage_status(room_id: int, u: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    """Get current stage mode status."""
    speakers = _stage_speakers.get(room_id)
    return {
        "stage_mode": speakers is not None,
        "speakers": list(speakers) if speakers else [],
        "is_speaker": u.id in speakers if speakers else True,
    }


# ==============================================================================
# WebRTC Media Configuration (noise/echo/blur/PiP)
# ==============================================================================

@router.get("/{room_id}/media-config")
async def media_config(room_id: int, u: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    """
    Return recommended media constraints for getUserMedia.
    Includes noise suppression, echo cancellation, background blur settings.

    Client applies these as MediaStreamConstraints:
      navigator.mediaDevices.getUserMedia(config.constraints)
    """
    _require_voice_room(room_id, db)
    count = get_voice_participant_count(room_id)

    return {
        "constraints": {
            "audio": {
                "echoCancellation": True,
                "noiseSuppression": True,
                "autoGainControl": True,
                "channelCount": 1,
                "sampleRate": 48000,
                "sampleSize": 16,
                # Advanced constraints for RNNoise-like processing
                "advanced": [
                    {"echoCancellation": {"exact": True}},
                    {"noiseSuppression": {"exact": True}},
                    {"autoGainControl": {"exact": True}},
                ],
            },
            "video": {
                "width": {"ideal": 1280, "max": 1920} if count <= 6 else {"ideal": 640, "max": 1280},
                "height": {"ideal": 720, "max": 1080} if count <= 6 else {"ideal": 360, "max": 720},
                "frameRate": {"ideal": 30, "max": 30} if count <= 6 else {"ideal": 15, "max": 24},
                "facingMode": "user",
            },
        },
        "features": {
            "noise_suppression": True,
            "echo_cancellation": True,
            "auto_gain_control": True,
            "background_blur": True,
            "virtual_background": True,
            "picture_in_picture": True,
            "screen_sharing": True,
        },
        "quality_presets": {
            "high": {"video_bitrate": 2500000, "audio_bitrate": 64000, "resolution": "1280x720"},
            "medium": {"video_bitrate": 800000, "audio_bitrate": 32000, "resolution": "640x360"},
            "low": {"video_bitrate": 200000, "audio_bitrate": 16000, "resolution": "320x180"},
            "audio_only": {"video_bitrate": 0, "audio_bitrate": 24000, "resolution": "none"},
        },
        "stage_mode": _stage_speakers.get(room_id) is not None,
        "recording": room_id in _voice_recordings,
    }


# ==============================================================================
# Voice-signal WebSocket (mesh topology signaling)
# ==============================================================================

@ws_router.websocket("/ws/voice-signal/{room_id}")
async def ws_voice_signal(
    websocket: WebSocket,
    room_id:   int,
    token:     Optional[str] = None,
    db:        Session       = Depends(get_db),
):
    """
    WebSocket for WebRTC signaling in voice channels (mesh topology).

    Flow:
      1. User calls POST /api/voice/{room_id}/join (adds to participants)
      2. User connects to this WS
      3. Server sends "voice_peers" listing all other connected signal peers
      4. New joiner creates OFFERs to every existing participant
      5. Existing participants send ANSWERs back
      6. On disconnect, user is auto-removed from voice participants

    Message format (client -> server):
      {type: "offer"|"answer"|"ice-candidate", to: user_id, ...payload}

    Message format (server -> client):
      {type: "voice_peers", peers: [{user_id, username, display_name, ...}]}
      {type: "offer"|"answer"|"ice-candidate", from: user_id, username: ..., ...payload}
      {type: "voice_peer_joined", user_id, username, display_name, ...}
      {type: "voice_peer_left", user_id, username}
      {type: "voice_mute", from: user_id, is_muted, is_video}
    """
    # Anti-probing: knock sequence in global mode
    from app.transport.knock import verify_knock, is_knock_required
    if is_knock_required():
        has_auth = bool(websocket.cookies.get("access_token"))
        if not has_auth:
            knock_token = websocket.query_params.get("knock") or websocket.cookies.get("_vk")
            if not verify_knock(knock_token):
                await websocket.close(code=1000)
                return

    # Authenticate
    raw_token = websocket.cookies.get("access_token") or token
    if not raw_token:
        await websocket.accept()
        await websocket.close(code=4401)
        return

    try:
        user = await get_user_ws(raw_token, db)
    except HTTPException:
        await websocket.accept()
        await websocket.close(code=4401)
        return

    # Verify user is a member and room is voice
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room or not getattr(room, "is_voice", False):
        await websocket.accept()
        await websocket.close(code=4400)
        return

    member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user.id,
        RoomMember.is_banned == False,
    ).first()
    if not member:
        await websocket.accept()
        await websocket.close(code=4403)
        return

    # Auto-join voice participants if not already joined
    if room_id not in _voice_participants or user.id not in _voice_participants.get(room_id, {}):
        participant = _make_participant(user)
        _voice_participants.setdefault(room_id, {})[user.id] = participant
        logger.info(f"Voice auto-join on signal WS: {user.username}({user.id}) -> room {room_id}")
        await _broadcast_voice_update(room_id, "join", participant)

    await websocket.accept()
    _voice_signal_rooms.setdefault(room_id, {})[user.id] = websocket
    logger.info(f"Voice signal WS+ {user.username}({user.id}) -> room {room_id}")

    try:
        # Send the list of already-connected signal peers to the new joiner
        existing_peers = []
        for uid, ws in _voice_signal_rooms.get(room_id, {}).items():
            if uid != user.id:
                p = _voice_participants.get(room_id, {}).get(uid)
                if p:
                    existing_peers.append({
                        "user_id":      p["user_id"],
                        "username":     p["username"],
                        "display_name": p["display_name"],
                        "avatar_emoji": p["avatar_emoji"],
                        "avatar_url":   p["avatar_url"],
                        "is_muted":     p["is_muted"],
                        "is_video":     p["is_video"],
                    })

        await websocket.send_text(_json.dumps({
            "type":  "voice_peers",
            "peers": existing_peers,
        }))

        # Notify existing peers that a new participant joined the signal mesh
        join_msg = _json.dumps({
            "type":         "voice_peer_joined",
            "user_id":      user.id,
            "username":     user.username,
            "display_name": user.display_name or user.username,
            "avatar_emoji": user.avatar_emoji or "\U0001f464",
            "avatar_url":   user.avatar_url,
            "is_muted":     _voice_participants.get(room_id, {}).get(user.id, {}).get("is_muted", False),
            "is_video":     _voice_participants.get(room_id, {}).get(user.id, {}).get("is_video", False),
        })
        for uid, ws in list(_voice_signal_rooms.get(room_id, {}).items()):
            if uid != user.id:
                try:
                    await ws.send_text(join_msg)
                except Exception as e:
                    logger.debug("Voice join broadcast: dead WS for user %s room %s: %s", uid, room_id, e)
                    _voice_signal_rooms.get(room_id, {}).pop(uid, None)

        # Main message loop: relay signaling messages between peers
        while True:
            raw = await websocket.receive_text()
            try:
                msg = _json.loads(raw)
            except Exception as e:
                logger.debug("Voice signal: invalid JSON from user %s room %s: %s", user.id, room_id, e)
                continue

            msg["from"]     = user.id
            msg["username"] = user.username

            # Targeted signaling: send only to the specified peer
            target_uid = msg.get("to")
            if target_uid and target_uid in _voice_signal_rooms.get(room_id, {}):
                try:
                    await _voice_signal_rooms[room_id][target_uid].send_text(_json.dumps(msg))
                except Exception as e:
                    logger.debug("Voice signal: dead WS for target %s room %s: %s", target_uid, room_id, e)
                    _voice_signal_rooms.get(room_id, {}).pop(target_uid, None)
            else:
                # Broadcast to all other signal peers in the room
                for uid, ws in list(_voice_signal_rooms.get(room_id, {}).items()):
                    if uid != user.id:
                        try:
                            await ws.send_text(_json.dumps(msg))
                        except Exception as e:
                            logger.debug("Voice broadcast: dead WS for user %s room %s: %s", uid, room_id, e)
                            _voice_signal_rooms.get(room_id, {}).pop(uid, None)

    except WebSocketDisconnect:
        logger.debug("Voice signal WS disconnect user=%s room=%s", user.username, room_id)
    except Exception as e:
        logger.warning(f"Voice signal WS error user={user.username} room={room_id}: {e}")
    finally:
        # Clean up signal WS
        sig_rooms = _voice_signal_rooms.get(room_id, {})
        sig_rooms.pop(user.id, None)
        if not sig_rooms and room_id in _voice_signal_rooms:
            _voice_signal_rooms.pop(room_id, None)

        logger.info(f"Voice signal WS- {user.username}({user.id}) <- room {room_id}")

        # Auto-leave voice channel on signal WS disconnect
        removed = await _remove_participant(room_id, user.id)
        if removed:
            logger.info(f"Voice auto-leave on signal disconnect: {user.username}({user.id}) <- room {room_id}")

            # Notify remaining signal peers
            leave_msg = _json.dumps({
                "type":     "voice_peer_left",
                "user_id":  user.id,
                "username": user.username,
            })
            for uid, ws in list(_voice_signal_rooms.get(room_id, {}).items()):
                try:
                    await ws.send_text(leave_msg)
                except Exception as e:
                    logger.debug("Voice leave broadcast: dead WS for user %s room %s: %s", uid, room_id, e)
                    _voice_signal_rooms.get(room_id, {}).pop(uid, None)

            # Broadcast to chat WS
            await _broadcast_voice_update(room_id, "leave", removed)

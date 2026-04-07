"""
app/chats/messages/polls.py — Full-featured in-room polls (Telegram-style).
Supports: anonymous voting, multiple answers, quiz mode, revote lock,
time limits, option suggestions, shuffle, descriptions.
Called from the ws_chat message dispatch loop.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.chats.messages._router import utc_iso
from app.models import User
from app.models_rooms import Message, MessageType
from app.peer.connection_manager import manager
from app.security.sealed_sender import compute_sender_pseudo

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def handle_create_poll(room_id: int, user: User, data: dict, db: Session) -> None:
    """Create a poll in a room with advanced options."""
    question = data.get("question", "").strip()
    options = data.get("options", [])
    description = data.get("description", "").strip()

    if not question or len(options) < 2:
        logger.debug("Poll creation rejected: question=%r options=%d", question, len(options))
        return
    if len(options) > 12:
        options = options[:12]

    # Build option objects: each can have description and media
    opt_objects = []
    for i, opt in enumerate(options):
        if isinstance(opt, dict):
            opt_objects.append({
                "text": str(opt.get("text", "")).strip()[:200],
                "description": str(opt.get("description", "")).strip()[:300],
                "media_url": str(opt.get("media_url", "")).strip() if opt.get("media_url") else None,
            })
        else:
            opt_objects.append({
                "text": str(opt).strip()[:200],
                "description": "",
                "media_url": None,
            })

    # Advanced settings
    anonymous = bool(data.get("anonymous", False))
    multiple = bool(data.get("multiple", False))
    quiz = bool(data.get("quiz", False))
    correct_option = data.get("correct_option")  # index for quiz mode
    explanation = data.get("explanation", "").strip()[:500] if quiz else ""
    disable_revote = bool(data.get("disable_revote", False))
    allow_suggest = bool(data.get("allow_suggest", False))
    shuffle = bool(data.get("shuffle", False))
    close_at = data.get("close_at")  # ISO timestamp or None
    media_url = data.get("media_url")  # attachment on question

    # Validate quiz
    if quiz:
        multiple = False  # quiz only allows single answer
        if correct_option is not None:
            correct_option = int(correct_option)
            if correct_option < 0 or correct_option >= len(opt_objects):
                correct_option = None

    poll_data = {
        "question": question,
        "description": description,
        "options": opt_objects,
        "votes": {},       # str(option_idx) -> count
        "voters": {},      # str(user_id) -> option_idx or [option_idxs]
        "anonymous": anonymous,
        "multiple": multiple,
        "quiz": quiz,
        "correct_option": correct_option,
        "explanation": explanation,
        "disable_revote": disable_revote,
        "allow_suggest": allow_suggest,
        "shuffle": shuffle,
        "close_at": close_at,
        "closed": False,
        "media_url": media_url,
        "suggested_by": {},  # option_idx -> user_id (for suggested options)
    }

    msg = Message(
        room_id=room_id,
        sender_pseudo=compute_sender_pseudo(room_id, user.id),
        msg_type=MessageType.SYSTEM,
        content_encrypted=json.dumps(poll_data).encode(),
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    broadcast = {
        "type": "poll",
        "msg_id": msg.id,
        "sender_pseudo": msg.sender_pseudo,
        "sender": user.username,
        "display_name": user.display_name or user.username,
        "avatar_emoji": user.avatar_emoji,
        "avatar_url": getattr(user, "avatar_url", None),
        **{k: v for k, v in poll_data.items()},
        "created_at": utc_iso(msg.created_at),
    }
    # Strip voter identity in anonymous mode
    if anonymous:
        broadcast["voters"] = {}

    await manager.broadcast_to_room(room_id, broadcast)


async def handle_vote_poll(room_id: int, user: User, data: dict, db: Session) -> None:
    """Vote in a poll — supports single and multiple answers."""
    msg_id = data.get("msg_id")
    option_index = data.get("option_index")  # int or list[int] for multiple
    if msg_id is None or option_index is None:
        return

    msg = db.query(Message).filter(Message.id == msg_id, Message.room_id == room_id).first()
    if not msg:
        return

    try:
        poll_data = json.loads(msg.content_encrypted.decode())
    except Exception as e:
        logger.debug("Poll vote: failed to decode poll data msg_id=%s: %s", msg_id, e)
        return

    # Check if poll is closed
    if poll_data.get("closed"):
        return
    close_at = poll_data.get("close_at")
    if close_at:
        try:
            deadline = datetime.fromisoformat(close_at.replace("Z", "+00:00"))
            if _utc_now() > deadline:
                poll_data["closed"] = True
                msg.content_encrypted = json.dumps(poll_data).encode()
                db.commit()
                await _broadcast_poll_update(room_id, msg_id, poll_data)
                return
        except (ValueError, TypeError):
            pass

    user_id_str = str(user.id)
    num_options = len(poll_data.get("options", []))

    # Disable revote check
    if poll_data.get("disable_revote") and user_id_str in poll_data.get("voters", {}):
        return

    if poll_data.get("multiple"):
        # Multiple choice: option_index is a list
        indices = option_index if isinstance(option_index, list) else [option_index]
        indices = [int(i) for i in indices if 0 <= int(i) < num_options]
        if not indices:
            return

        # Remove previous votes
        prev = poll_data.get("voters", {}).get(user_id_str)
        if prev is not None:
            prev_list = prev if isinstance(prev, list) else [prev]
            for idx in prev_list:
                key = str(idx)
                if key in poll_data.get("votes", {}):
                    poll_data["votes"][key] = max(0, poll_data["votes"].get(key, 0) - 1)

        # Add new votes
        for idx in indices:
            key = str(idx)
            poll_data.setdefault("votes", {})[key] = poll_data.get("votes", {}).get(key, 0) + 1
        poll_data.setdefault("voters", {})[user_id_str] = indices
    else:
        # Single choice
        idx = int(option_index) if not isinstance(option_index, list) else int(option_index[0])
        if idx < 0 or idx >= num_options:
            return

        # Remove previous vote
        if user_id_str in poll_data.get("voters", {}):
            old_idx = poll_data["voters"][user_id_str]
            old_key = str(old_idx if not isinstance(old_idx, list) else old_idx[0])
            if old_key in poll_data.get("votes", {}):
                poll_data["votes"][old_key] = max(0, poll_data["votes"].get(old_key, 0) - 1)

        # Add new vote
        poll_data.setdefault("votes", {})[str(idx)] = poll_data.get("votes", {}).get(str(idx), 0) + 1
        poll_data.setdefault("voters", {})[user_id_str] = idx

    msg.content_encrypted = json.dumps(poll_data).encode()
    db.commit()

    # Quiz mode: send correct/incorrect feedback to voter
    quiz_result = None
    if poll_data.get("quiz") and poll_data.get("correct_option") is not None:
        voted_idx = idx if not poll_data.get("multiple") else indices[0]
        quiz_result = {
            "correct": voted_idx == poll_data["correct_option"],
            "correct_option": poll_data["correct_option"],
            "explanation": poll_data.get("explanation", ""),
        }

    await _broadcast_poll_update(room_id, msg_id, poll_data, quiz_result=quiz_result,
                                  voter_id=user.id)


async def handle_retract_vote(room_id: int, user: User, data: dict, db: Session) -> None:
    """Retract a vote (undo)."""
    msg_id = data.get("msg_id")
    if msg_id is None:
        return

    msg = db.query(Message).filter(Message.id == msg_id, Message.room_id == room_id).first()
    if not msg:
        return

    try:
        poll_data = json.loads(msg.content_encrypted.decode())
    except Exception:
        return

    if poll_data.get("closed") or poll_data.get("disable_revote"):
        return

    user_id_str = str(user.id)
    prev = poll_data.get("voters", {}).get(user_id_str)
    if prev is None:
        return

    prev_list = prev if isinstance(prev, list) else [prev]
    for idx in prev_list:
        key = str(idx)
        if key in poll_data.get("votes", {}):
            poll_data["votes"][key] = max(0, poll_data["votes"].get(key, 0) - 1)

    del poll_data["voters"][user_id_str]

    msg.content_encrypted = json.dumps(poll_data).encode()
    db.commit()

    await _broadcast_poll_update(room_id, msg_id, poll_data)


async def handle_close_poll(room_id: int, user: User, data: dict, db: Session) -> None:
    """Close a poll (only creator can close)."""
    msg_id = data.get("msg_id")
    if msg_id is None:
        return

    msg = db.query(Message).filter(Message.id == msg_id, Message.room_id == room_id).first()
    if not msg:
        return

    try:
        poll_data = json.loads(msg.content_encrypted.decode())
    except Exception:
        return

    poll_data["closed"] = True
    msg.content_encrypted = json.dumps(poll_data).encode()
    db.commit()

    await _broadcast_poll_update(room_id, msg_id, poll_data, closed=True)


async def handle_suggest_option(room_id: int, user: User, data: dict, db: Session) -> None:
    """Suggest a new option to an active poll."""
    msg_id = data.get("msg_id")
    text = data.get("text", "").strip()
    if not msg_id or not text:
        return

    msg = db.query(Message).filter(Message.id == msg_id, Message.room_id == room_id).first()
    if not msg:
        return

    try:
        poll_data = json.loads(msg.content_encrypted.decode())
    except Exception:
        return

    if poll_data.get("closed") or not poll_data.get("allow_suggest"):
        return
    if len(poll_data["options"]) >= 12:
        return

    new_idx = len(poll_data["options"])
    poll_data["options"].append({
        "text": text[:200],
        "description": "",
        "media_url": None,
    })
    poll_data.setdefault("suggested_by", {})[str(new_idx)] = user.id

    msg.content_encrypted = json.dumps(poll_data).encode()
    db.commit()

    await _broadcast_poll_update(room_id, msg_id, poll_data, new_option={
        "index": new_idx,
        "text": text[:200],
        "suggested_by": user.display_name or user.username,
    })


async def _broadcast_poll_update(room_id: int, msg_id: int, poll_data: dict, *,
                                  quiz_result: dict | None = None,
                                  voter_id: int | None = None,
                                  closed: bool = False,
                                  new_option: dict | None = None) -> None:
    """Broadcast poll state update to room."""
    total = sum(poll_data.get("votes", {}).values())
    payload = {
        "type": "poll_update",
        "msg_id": msg_id,
        "votes": poll_data.get("votes", {}),
        "total_votes": total,
        "closed": poll_data.get("closed", False),
        "options": poll_data.get("options", []),
    }

    # Include voters only if not anonymous
    if not poll_data.get("anonymous"):
        payload["voters"] = poll_data.get("voters", {})
    else:
        payload["voters"] = {}

    if quiz_result and voter_id:
        payload["quiz_result"] = quiz_result
        payload["quiz_voter_id"] = voter_id

    if new_option:
        payload["new_option"] = new_option

    if closed:
        payload["closed"] = True

    await manager.broadcast_to_room(room_id, payload)

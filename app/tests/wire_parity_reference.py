"""Вторая независимая реализация правил среза 2 `vortex-proto` на Python.

Ничего не импортирует из `vortex_chat` и из `app.*` намеренно: вектора паритета
имеют смысл только тогда, когда обе стороны считают правило сами. Здесь описаны:

  * обёртка комнатного ключа (классический ECIES и post-quantum гибрид);
  * конверт сообщения (границы шифротекста, версия, метка времени, упоминания);
  * формы исходящих конвертов (ack, message, thread_message, edited, deleted,
    thread_update, хранимое сообщение);
  * настройки комнаты (имя, описание, аватар, антиспам, реакции, тема) и форма
    ответа о комнате.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

MIN_CIPHERTEXT_HEX = 48
MAX_CIPHERTEXT_HEX = 65536
MAX_MENTIONS = 20
MENTION_MIN_LEN = 3
MENTION_MAX_LEN = 30
CLIENT_STAMP_WINDOW_SECS = 300

X25519_HEX_LEN = 64
KYBER_CIPHERTEXT_HEX_LEN = 2176
WRAP_CIPHERTEXT_MIN_HEX = 24

NAME_MAX_LEN = 100
DESCRIPTION_MAX_LEN = 500
AVATAR_MAX_LEN = 10
ALLOWED_REACTIONS_MAX_LEN = 500
DEFAULT_AVATAR = "\U0001f4ac"
VOICE_AVATAR = "\U0001f50a"

WALLPAPERS = ("none", "stars", "aurora", "sunset", "ocean-wave", "mesh", "deep-space")
ANTISPAM_THRESHOLDS = (5, 10, 15)
ANTISPAM_ACTIONS = ("warn", "mute", "kick", "ban")
REACTIONS_TYPES = ("all", "selected", "off")
REPLICATION_MODES = ("none", "federated")

_HEX = re.compile(r"\A(?:[0-9a-fA-F]{2})*\Z")
_ACCENT = re.compile(r"\A#[0-9a-fA-F]{6}\Z")


def is_hex(text: str) -> bool:
    return bool(_HEX.match(text))


def unhex(text: str) -> bytes | None:
    return bytes.fromhex(text) if is_hex(text) else None


# Обёртка комнатного ключа


def wrap_parse(payload: dict) -> dict | None:
    """Разбор конверта ключа. None — конверт негоден."""
    ciphertext = payload.get("ciphertext") or ""
    if not isinstance(ciphertext, str) or not is_hex(ciphertext):
        return None
    if len(ciphertext) < WRAP_CIPHERTEXT_MIN_HEX:
        return None

    kyber = payload.get("kyber_ciphertext") or ""
    hybrid = bool(payload.get("hybrid")) or bool(kyber)

    if not hybrid:
        ephemeral = payload.get("ephemeral_pub") or ""
        if not _is_ephemeral(ephemeral):
            return None
        return {"hybrid": False, "ephemeral_pub": _canonical(ephemeral), "ciphertext": _canonical(ciphertext)}

    if not kyber or not is_hex(kyber) or len(kyber) != KYBER_CIPHERTEXT_HEX_LEN:
        return None
    ephemeral = payload.get("x25519_ephemeral_pub") or ""
    if not _is_ephemeral(ephemeral):
        return None
    return {
        "hybrid": True,
        "ephemeral_pub": _canonical(ephemeral),
        "kyber_ciphertext": _canonical(kyber),
        "ciphertext": _canonical(ciphertext),
    }


def _canonical(text: str) -> str:
    """Hex конверта канонизируется: разбор в байты и обратная печать в нижнем регистре."""
    return bytes.fromhex(text).hex()


def _is_ephemeral(text: object) -> bool:
    return isinstance(text, str) and len(text) == X25519_HEX_LEN and is_hex(text)


def wrap_client_dict(parsed: dict) -> dict:
    """Форма конверта для клиента."""
    if parsed["hybrid"]:
        return {
            "hybrid": True,
            "x25519_ephemeral_pub": parsed["ephemeral_pub"],
            "kyber_ciphertext": parsed["kyber_ciphertext"],
            "ciphertext": parsed["ciphertext"],
        }
    return {"ephemeral_pub": parsed["ephemeral_pub"], "ciphertext": parsed["ciphertext"]}


def wrap_stored(ephemeral_pub: str, ciphertext: str, kyber_ciphertext: str | None) -> dict:
    """Форма хранимой строки для клиента: гибрид ⟺ есть kyber_ciphertext."""
    if kyber_ciphertext:
        return {
            "hybrid": True,
            "x25519_ephemeral_pub": ephemeral_pub,
            "kyber_ciphertext": kyber_ciphertext,
            "ciphertext": ciphertext,
        }
    return {"ephemeral_pub": ephemeral_pub, "ciphertext": ciphertext}


# Метки времени


def wire_stamp(microseconds: int) -> str:
    moment = EPOCH + timedelta(microseconds=microseconds - microseconds % 1_000_000)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def stored_stamp(microseconds: int) -> str:
    moment = EPOCH + timedelta(microseconds=microseconds)
    return moment.replace(tzinfo=None).isoformat()


def client_stamp(text: str, now_microseconds: int) -> int | None:
    """Разбор клиентской метки и окно ±5 минут."""
    stamp = _read_stamp(text)
    if stamp is None:
        return None
    window = CLIENT_STAMP_WINDOW_SECS * 1_000_000
    return stamp if abs(now_microseconds - stamp) <= window else None


def _read_stamp(text: str) -> int | None:
    if not isinstance(text, str) or not text:
        return None
    body = text
    offset = 0
    if body.endswith(("Z", "z")):
        body = body[:-1]
    else:
        sign_at = _offset_start(body)
        if sign_at is not None:
            sign = -1 if body[sign_at] == "-" else 1
            offset = _read_offset(body[sign_at + 1 :])
            if offset is None:
                return None
            offset *= sign
            body = body[:sign_at]
    moment = _read_moment(body)
    if moment is None:
        return None
    return moment - offset * 1_000_000


def _offset_start(body: str) -> int | None:
    for index in range(10, len(body)):
        if body[index] in "+-":
            return index
    return None


def _read_offset(text: str) -> int | None:
    digits = text.replace(":", "")
    if not digits.isdigit() or len(digits) not in (2, 4, 6):
        return None
    hours = int(digits[0:2])
    minutes = int(digits[2:4]) if len(digits) >= 4 else 0
    seconds = int(digits[4:6]) if len(digits) == 6 else 0
    if hours > 23 or minutes > 59 or seconds > 59:
        return None
    return hours * 3600 + minutes * 60 + seconds


def _read_moment(body: str) -> int | None:
    if len(body) < 10 or body[4] != "-" or body[7] != "-":
        return None
    if not (body[0:4].isdigit() and body[5:7].isdigit() and body[8:10].isdigit()):
        return None
    try:
        day = datetime(int(body[0:4]), int(body[5:7]), int(body[8:10]), tzinfo=timezone.utc)
    except ValueError:
        return None

    rest = body[10:]
    if not rest:
        return int((day - EPOCH).total_seconds()) * 1_000_000
    if rest[0] not in ("T", "t", " "):
        return None
    clock = rest[1:]
    if len(clock) < 5 or clock[2] != ":" or not (clock[0:2].isdigit() and clock[3:5].isdigit()):
        return None
    hour, minute, second, micros = int(clock[0:2]), int(clock[3:5]), 0, 0
    if len(clock) > 5:
        if clock[5] != ":" or len(clock) < 8 or not clock[6:8].isdigit():
            return None
        second = int(clock[6:8])
        if len(clock) > 8:
            if clock[8] not in (".", ","):
                return None
            fraction = clock[9:]
            if not fraction.isdigit():
                return None
            micros = int((fraction + "000000")[:6])
    if hour > 23 or minute > 59 or second > 60:
        return None
    second = min(second, 59)
    moment = day + timedelta(hours=hour, minutes=minute, seconds=second)
    return int((moment - EPOCH).total_seconds()) * 1_000_000 + micros


# Конверт сообщения

REFUSALS = {
    "ciphertext_required": "Ciphertext is required",
    "ciphertext_short": "Ciphertext too short",
    "ciphertext_large": "Ciphertext too large",
    "ciphertext_hex": "Ciphertext is not valid hex",
    "message_id_required": "Message id is required",
    "thread_id_required": "Thread id is required",
    "frame_too_large": "Message too large",
}


def message_read(frame: dict, action: str, now_microseconds: int) -> dict:
    """Разбор входящего кадра. В ответе либо refusal, либо разобранные поля."""
    if action == "delete_message":
        msg_id = _read_id(frame.get("msg_id"))
        if msg_id is None:
            return {"refusal": "message_id_required"}
        return {"refusal": None, "msg_id": msg_id}

    if action == "edit_message":
        msg_id = _read_id(frame.get("msg_id"))
        if msg_id is None:
            return {"refusal": "message_id_required"}
        content = _read_content(frame)
        if "refusal" in content:
            return {"refusal": content["refusal"]}
        return {"refusal": None, "msg_id": msg_id, **content}

    thread_id = None
    if action == "thread_reply":
        thread_id = _read_id(frame.get("thread_id"))
        if thread_id is None:
            return {"refusal": "thread_id_required"}

    content = _read_content(frame)
    if "refusal" in content:
        return {"refusal": content["refusal"]}

    quote = frame.get("reply_quote")
    parsed = {
        "refusal": None,
        "client_msg_id": _scalar_text(frame.get("msg_id")),
        "reply_to_id": _read_id(frame.get("reply_to_id")),
        "reply_quote": quote if isinstance(quote, str) and quote else None,
        "mentions": _read_mentions(frame.get("mentioned_usernames")),
        "client_ts_us": client_stamp(frame.get("client_ts") or "", now_microseconds),
        **content,
    }
    if thread_id is not None:
        parsed["thread_id"] = thread_id
    return parsed


def _read_content(frame: dict) -> dict:
    raw = frame.get("ciphertext")
    text = raw.strip() if isinstance(raw, str) else ""
    if not text:
        return {"refusal": "ciphertext_required"}
    if len(text) < MIN_CIPHERTEXT_HEX:
        return {"refusal": "ciphertext_short"}
    if len(text) > MAX_CIPHERTEXT_HEX:
        return {"refusal": "ciphertext_large"}
    content = unhex(text)
    if content is None:
        return {"refusal": "ciphertext_hex"}

    digest = _blake3(content)
    claim = frame.get("hash")
    if not isinstance(claim, str) or not claim:
        claim_kind = "absent"
    elif len(claim) == 64 and is_hex(claim) and bytes.fromhex(claim) == digest:
        claim_kind = "truthful"
    else:
        claim_kind = "untruthful"

    return {
        "ciphertext": content.hex(),
        "digest_hex": digest.hex(),
        "digest_claim": claim_kind,
        "enc_v": _read_enc_v(frame.get("enc_v")),
    }


def _blake3(content: bytes) -> bytes:
    from blake3 import blake3

    return blake3(content).digest()


def _read_enc_v(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= 255 else None


def _read_id(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        signed = text[1:] if text[:1] in "+-" else text
        return int(text) if signed.isdigit() else None
    return None


def _scalar_text(value: object) -> str:
    if isinstance(value, bool):
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return json.dumps(value)
    return ""


def _read_mentions(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    kept = []
    for entry in value[:MAX_MENTIONS]:
        if not isinstance(entry, str):
            continue
        if MENTION_MIN_LEN <= len(entry) <= MENTION_MAX_LEN:
            kept.append(entry.lower().strip())
    return kept


# Исходящие конверты


def ack(client_msg_id: str, server_id: int, created_at_us: int) -> dict:
    return {
        "type": "ack",
        "msg_id": client_msg_id,
        "server_id": server_id,
        "created_at": wire_stamp(created_at_us),
    }


def ack_duplicate(client_msg_id: str) -> dict:
    return {"type": "ack", "msg_id": client_msg_id, "duplicate": True}


def sent_message(**fields) -> dict:
    return {
        "type": "message",
        "msg_id": fields["msg_id"],
        "client_msg_id": fields["client_msg_id"],
        "sender_id": fields.get("sender_id"),
        "sender_pseudo": fields.get("sender_pseudo"),
        "sender": fields.get("sender") or "",
        "display_name": fields.get("display_name") or fields.get("sender") or "",
        "avatar_emoji": fields.get("avatar_emoji"),
        "avatar_url": fields.get("avatar_url"),
        "is_bot": bool(fields.get("is_bot")),
        "tag": fields.get("tag"),
        "tag_color": fields.get("tag_color"),
        "reply_color": fields.get("reply_color"),
        "reply_icon": fields.get("reply_icon"),
        "ciphertext": fields["ciphertext"],
        "hash": fields["digest_hex"],
        "enc_v": fields.get("enc_v"),
        "reply_to_id": fields.get("reply_to_id"),
        "reply_quote": fields.get("reply_quote"),
        "status": "sent",
        "forwarded_from": fields.get("forwarded_from"),
        "expires_at": None if fields.get("expires_at_us") is None else wire_stamp(fields["expires_at_us"]),
        "created_at": wire_stamp(fields["created_at_us"]),
    }


def thread_message(**fields) -> dict:
    return {
        "type": "thread_message",
        "msg_id": fields["msg_id"],
        "client_msg_id": fields["client_msg_id"],
        "sender_pseudo": fields.get("sender_pseudo"),
        "sender": fields.get("sender") or "",
        "display_name": fields.get("display_name") or fields.get("sender") or "",
        "avatar_emoji": fields.get("avatar_emoji"),
        "avatar_url": fields.get("avatar_url"),
        "ciphertext": fields["ciphertext"],
        "hash": fields["digest_hex"],
        "enc_v": fields.get("enc_v"),
        "reply_to_id": fields.get("reply_to_id"),
        "reply_quote": fields.get("reply_quote"),
        "thread_id": fields["thread_id"],
        "status": "sent",
        "created_at": wire_stamp(fields["created_at_us"]),
    }


def edited_message(msg_id: int, ciphertext: str, enc_v: int | None) -> dict:
    return {
        "type": "message_edited",
        "msg_id": msg_id,
        "ciphertext": ciphertext,
        "enc_v": enc_v,
        "is_edited": True,
    }


def deleted_message(msg_id: int) -> dict:
    return {"type": "message_deleted", "msg_id": msg_id}


def thread_update(msg_id: int, thread_count: int | None) -> dict:
    return {"type": "thread_update", "msg_id": msg_id, "thread_count": thread_count or 0}


def error_frame(code: str) -> dict:
    return {"type": "error", "message": REFUSALS[code], "code": code}


def stored_message(**fields) -> dict:
    content = fields.get("content")
    digest = fields.get("digest")
    expires_at_us = fields.get("expires_at_us")
    return {
        "msg_id": fields["msg_id"],
        "sender_pseudo": fields.get("sender_pseudo"),
        "msg_type": fields["msg_type"],
        "ciphertext": None if content is None else bytes(content).hex(),
        "hash": None if digest is None else bytes(digest).hex(),
        "enc_v": fields.get("enc_v"),
        "file_name": fields.get("file_name"),
        "file_size": fields.get("file_size"),
        "reply_to_id": fields.get("reply_to_id"),
        "thread_id": fields.get("thread_id"),
        "thread_count": fields.get("thread_count") or 0,
        "is_edited": bool(fields.get("is_edited")),
        "forwarded_from": fields.get("forwarded_from"),
        "expires_at": None if expires_at_us is None else stored_stamp(expires_at_us),
        "created_at": stored_stamp(fields["created_at_us"]),
    }


# Комната


def room_name(text: str) -> str | None:
    trimmed = text.strip()
    return trimmed if 1 <= len(trimmed) <= NAME_MAX_LEN else None


def room_description(text: str) -> str | None:
    trimmed = text.strip()
    return trimmed if len(trimmed) <= DESCRIPTION_MAX_LEN else None


def room_avatar_given(is_voice: bool) -> str:
    return VOICE_AVATAR if is_voice else DEFAULT_AVATAR


def room_replication_mode(text: str) -> str | None:
    return text if text in REPLICATION_MODES else None


def room_antispam_config(payload: str) -> str | None:
    try:
        parsed = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    safe = {}
    threshold = parsed.get("threshold")
    if isinstance(threshold, int) and not isinstance(threshold, bool) and threshold in ANTISPAM_THRESHOLDS:
        safe["threshold"] = threshold
    action = parsed.get("action")
    if isinstance(action, str) and action in ANTISPAM_ACTIONS:
        safe["action"] = action
    if "block_repeats" in parsed:
        safe["block_repeats"] = bool(parsed["block_repeats"])
    if "block_links" in parsed:
        safe["block_links"] = bool(parsed["block_links"])
    return json.dumps(safe, separators=(",", ":"))


def room_theme(wallpaper: str | None, accent: str | None, dark_mode: bool | None) -> str:
    """Сериализованная тема; бросает ValueError на негодном поле."""
    parts = []
    if wallpaper is not None:
        if wallpaper not in WALLPAPERS and not wallpaper.startswith("https://"):
            raise ValueError(f"Invalid wallpaper: {wallpaper}")
        parts.append(f"\"wallpaper\":{json.dumps(wallpaper, ensure_ascii=False)}")
    if accent is not None:
        if not _ACCENT.match(accent):
            raise ValueError("Invalid accent")
        parts.append(f"\"accent\":\"{accent}\"")
    if dark_mode is not None:
        parts.append(f"\"dark_mode\":{json.dumps(dark_mode)}")
    return "{" + ",".join(parts) + "}"


def room_settings(patch: dict) -> dict:
    """Разбор патча настроек: либо refusal, либо применяемые значения."""
    out: dict = {"refusal": None}

    if patch.get("name") is not None:
        name = room_name(patch["name"])
        if name is None:
            return {"refusal": "Invalid room name"}
        out["name"] = name
    if patch.get("description") is not None:
        description = room_description(patch["description"])
        if description is None:
            return {"refusal": "Invalid room description"}
        out["description"] = description
    if patch.get("avatar_emoji") is not None:
        avatar = patch["avatar_emoji"]
        if len(avatar) > AVATAR_MAX_LEN:
            return {"refusal": "Invalid room avatar"}
        out["avatar_emoji"] = avatar
    if patch.get("auto_delete_seconds") is not None:
        seconds = patch["auto_delete_seconds"]
        out["auto_delete_given"] = True
        out["auto_delete_seconds"] = seconds if seconds > 0 else None
    if patch.get("slow_mode_seconds") is not None:
        out["slow_mode_seconds"] = max(0, patch["slow_mode_seconds"])
    if patch.get("antispam_config") is not None:
        config = room_antispam_config(patch["antispam_config"])
        out["antispam_config"] = config
        out["antispam_config_refused"] = config is None
    if patch.get("reactions_type") is not None:
        if patch["reactions_type"] not in REACTIONS_TYPES:
            return {"refusal": "Invalid reactions_type"}
        out["reactions_type"] = patch["reactions_type"]
    if patch.get("allowed_reactions") is not None:
        if len(patch["allowed_reactions"]) > ALLOWED_REACTIONS_MAX_LEN:
            return {"refusal": "Invalid allowed_reactions"}
        out["allowed_reactions"] = patch["allowed_reactions"]
    return out


def room_view(**row) -> dict:
    view = {
        "id": row["id"],
        "name": row["name"],
        "description": row.get("description") or "",
        "is_private": bool(row.get("is_private")),
        "is_channel": bool(row.get("is_channel")),
        "is_voice": bool(row.get("is_voice")),
        "invite_code": row.get("invite_code"),
        "member_count": row["member_count"],
        "online_count": row["online_count"],
        "avatar_emoji": row.get("avatar_emoji") or DEFAULT_AVATAR,
        "avatar_url": row.get("avatar_url"),
        "auto_delete_seconds": row.get("auto_delete_seconds"),
        "slow_mode_seconds": max(0, row.get("slow_mode_seconds") or 0),
        "antispam_enabled": True if row.get("antispam_enabled") is None else bool(row["antispam_enabled"]),
        "antispam_config": row.get("antispam_config") or "{}",
        "creator_id": row.get("creator_id"),
        "created_at": stored_stamp(row["created_at_us"]),
        "theme_json": row.get("theme_json"),
        "discussion_enabled": bool(row.get("discussion_enabled")),
        "reactions_type": row.get("reactions_type") or "all",
        "allowed_reactions": row.get("allowed_reactions") or "",
        "admin_signatures": bool(row.get("admin_signatures")),
        "copy_protection": bool(row.get("copy_protection")),
        "silent_default": bool(row.get("silent_default")),
        "join_approval": bool(row.get("join_approval")),
        "hashtags_enabled": True if row.get("hashtags_enabled") is None else bool(row["hashtags_enabled"]),
        "replication_mode": row.get("replication_mode") or "none",
        "is_dm": bool(row.get("is_dm")),
    }
    if view["is_voice"]:
        participants = row.get("voice_participants") or []
        view["voice_participants"] = participants
        view["voice_participant_count"] = len(participants)
    return view

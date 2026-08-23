#!/usr/bin/env python3
"""Генератор замороженных векторов среза 2 `vortex-proto`.

Считает эталонные значения второй Python-реализацией
(`app/tests/wire_parity_reference.py`) и пишет их в
`app/tests/vectors/wire_parity.json`. Rust сверяется с этим файлом в
`app/tests/test_wire_parity.py`.

Запуск:  python scripts/gen_wire_parity_vectors.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.tests import wire_parity_reference as ref  # noqa: E402

OUT = ROOT / "app" / "tests" / "vectors" / "wire_parity.json"

EPH = "1a" * 32
CT = "2b" * 60
KYBER = "3c" * 1088
MESSAGE_CT = "ab" * 30
NOW_US = 1_785_834_930_000_000


def wrap_cases() -> list[dict]:
    payloads = [
        {"ephemeral_pub": EPH, "ciphertext": CT},
        {"ephemeral_pub": EPH, "ciphertext": "aa" * 12},
        {"ephemeral_pub": EPH.upper(), "ciphertext": CT},
        {"hybrid": True, "x25519_ephemeral_pub": EPH, "kyber_ciphertext": KYBER, "ciphertext": CT},
        {"ephemeral_pub": EPH, "kyber_ciphertext": KYBER, "ciphertext": CT},
        {"hybrid": True, "x25519_ephemeral_pub": EPH, "ciphertext": CT},
        {"hybrid": True, "x25519_ephemeral_pub": EPH, "kyber_ciphertext": "3c" * 50, "ciphertext": CT},
        {"ephemeral_pub": "1a" * 31 + "  ", "ciphertext": CT},
        {"ephemeral_pub": "1a" * 31, "ciphertext": CT},
        {"ephemeral_pub": "zz" * 32, "ciphertext": CT},
        {"ciphertext": CT},
        {"ephemeral_pub": EPH, "ciphertext": "aa" * 11},
        {"ephemeral_pub": EPH, "ciphertext": "a" * 25},
        {"ephemeral_pub": EPH, "ciphertext": ""},
        {"ephemeral_pub": "", "ciphertext": CT},
    ]
    cases = []
    for payload in payloads:
        parsed = ref.wrap_parse(payload)
        cases.append(
            {
                "payload": payload,
                "accepted": parsed is not None,
                "client": None if parsed is None else ref.wrap_client_dict(parsed),
            }
        )
    return cases


def wrap_stored_cases() -> list[dict]:
    rows = [
        (EPH, CT, None),
        (EPH, CT, ""),
        (EPH, CT, KYBER),
    ]
    return [
        {
            "ephemeral_pub": eph,
            "ciphertext": ct,
            "kyber_ciphertext": kyber,
            "client": ref.wrap_stored(eph, ct, kyber),
        }
        for eph, ct, kyber in rows
    ]


def message_cases() -> list[dict]:
    frames = [
        ("message", {"action": "message", "ciphertext": MESSAGE_CT, "msg_id": "c-1"}),
        ("message", {"ciphertext": MESSAGE_CT, "enc_v": 2, "client_ts": "2026-08-04T09:15:30.789Z"}),
        ("message", {"ciphertext": MESSAGE_CT, "client_ts": "2020-01-01T00:00:00Z"}),
        ("message", {"ciphertext": MESSAGE_CT, "client_ts": "2026-08-04T12:15:30+03:00"}),
        ("message", {"ciphertext": f"  {MESSAGE_CT}  ", "msg_id": 7}),
        ("message", {"ciphertext": MESSAGE_CT, "reply_to_id": "12", "reply_quote": "hi"}),
        ("message", {"ciphertext": MESSAGE_CT, "reply_to_id": True}),
        ("message", {"ciphertext": MESSAGE_CT, "mentioned_usernames": ["Alice", "ab", " bob ", 5]}),
        ("message", {"ciphertext": MESSAGE_CT, "mentioned_usernames": [f"user{i:02}" for i in range(25)]}),
        ("message", {"ciphertext": MESSAGE_CT, "mentioned_usernames": "alice"}),
        ("message", {"ciphertext": MESSAGE_CT, "enc_v": 256}),
        ("message", {"ciphertext": MESSAGE_CT, "enc_v": True}),
        ("message", {"ciphertext": MESSAGE_CT, "enc_v": "1"}),
        ("message", {"ciphertext": MESSAGE_CT, "hash": "11" * 32}),
        ("message", {"ciphertext": MESSAGE_CT, "hash": "zz"}),
        ("message", {"ciphertext": ""}),
        ("message", {"ciphertext": "   "}),
        ("message", {}),
        ("message", {"ciphertext": "ab" * 20}),
        ("message", {"ciphertext": "a" * 49}),
        ("message", {"ciphertext": "ab " + "ab" * 30}),
        ("thread_reply", {"thread_id": 5, "ciphertext": MESSAGE_CT, "msg_id": "c-2"}),
        ("thread_reply", {"thread_id": "5", "ciphertext": MESSAGE_CT}),
        ("thread_reply", {"ciphertext": MESSAGE_CT}),
        ("thread_reply", {"thread_id": 5}),
        ("edit_message", {"msg_id": 9, "ciphertext": MESSAGE_CT, "enc_v": 1}),
        ("edit_message", {"ciphertext": MESSAGE_CT}),
        ("edit_message", {"msg_id": 9, "ciphertext": "abcd"}),
        ("edit_message", {"msg_id": "9", "ciphertext": MESSAGE_CT}),
        ("delete_message", {"msg_id": 9}),
        ("delete_message", {"msg_id": "abc"}),
        ("delete_message", {}),
    ]
    return [
        {"action": action, "frame": frame, "now_us": NOW_US, "parsed": ref.message_read(frame, action, NOW_US)}
        for action, frame in frames
    ]


def stamp_cases() -> list[dict]:
    texts = [
        "2026-08-04T09:15:30.789Z",
        "2026-08-04T09:15:30Z",
        "2026-08-04T09:15:30",
        "2026-08-04T12:15:30+03:00",
        "2026-08-04T06:15:30-0300",
        "2026-08-04T09:15Z",
        "2026-08-04T09:15:30.123456789Z",
        "2026-08-04 09:15:30Z",
        "2026-08-04",
        "2025-02-29T00:00:00Z",
        "20260804T091530Z",
        "2026-8-4T09:15:30Z",
        "2026-08-04T25:15:30Z",
        "2026-08-04T09:15:30+99:00",
        "",
        "not a date",
    ]
    return [{"text": text, "now_us": NOW_US, "stamp_us": ref.client_stamp(text, NOW_US)} for text in texts]


def wire_stamp_cases() -> list[dict]:
    moments = [0, 1_000_000, NOW_US, NOW_US + 789_012, 1_709_208_000_000_000, 2_147_483_647_000_000]
    return [
        {"microseconds": us, "wire": ref.wire_stamp(us), "stored": ref.stored_stamp(us)} for us in moments
    ]


def relay_cases() -> dict:
    digest = ref._blake3(bytes.fromhex(MESSAGE_CT)).hex()
    sent = {
        "msg_id": 42,
        "client_msg_id": "c-1",
        "ciphertext": MESSAGE_CT,
        "digest_hex": digest,
        "created_at_us": NOW_US,
        "sender_id": 3,
        "sender_pseudo": "pseudo",
        "sender": "alice",
        "display_name": None,
        "avatar_emoji": None,
        "avatar_url": None,
        "is_bot": False,
        "tag": None,
        "tag_color": None,
        "reply_color": None,
        "reply_icon": None,
        "enc_v": 2,
        "reply_to_id": 7,
        "reply_quote": "hi",
        "forwarded_from": None,
        "expires_at_us": NOW_US + 60_000_000,
    }
    thread = {
        "msg_id": 43,
        "client_msg_id": "c-2",
        "thread_id": 42,
        "ciphertext": MESSAGE_CT,
        "digest_hex": digest,
        "created_at_us": NOW_US,
        "sender_pseudo": "pseudo",
        "sender": "bob",
        "display_name": "Bob B.",
        "avatar_emoji": "🙂",
        "avatar_url": None,
        "enc_v": None,
        "reply_to_id": None,
        "reply_quote": None,
    }
    stored = {
        "msg_id": 42,
        "msg_type": "text",
        "created_at_us": NOW_US + 789_012,
        "sender_pseudo": "pseudo",
        "content": list(bytes.fromhex(MESSAGE_CT)),
        "digest": list(bytes.fromhex(digest)),
        "enc_v": 1,
        "file_name": None,
        "file_size": None,
        "reply_to_id": None,
        "thread_id": None,
        "thread_count": None,
        "is_edited": None,
        "forwarded_from": None,
        "expires_at_us": NOW_US,
    }
    return {
        "ack": {"input": ["c-1", 42, NOW_US], "payload": ref.ack("c-1", 42, NOW_US)},
        "ack_duplicate": {"input": ["c-1"], "payload": ref.ack_duplicate("c-1")},
        "sent": {"input": sent, "payload": ref.sent_message(**sent)},
        "thread": {"input": thread, "payload": ref.thread_message(**thread)},
        "edited": {"input": [9, MESSAGE_CT, 1], "payload": ref.edited_message(9, MESSAGE_CT, 1)},
        "deleted": {"input": [9], "payload": ref.deleted_message(9)},
        "thread_update": {"input": [42, None], "payload": ref.thread_update(42, None)},
        "stored": {"input": stored, "payload": ref.stored_message(**stored)},
        "errors": {code: ref.error_frame(code) for code in ref.REFUSALS},
    }


def room_cases() -> dict:
    patches = [
        {"name": "  General  "},
        {"name": "   "},
        {"name": "x" * 101},
        {"description": "  hi "},
        {"description": "d" * 501},
        {"avatar_emoji": "a" * 11},
        {"auto_delete_seconds": 0},
        {"auto_delete_seconds": 30},
        {"slow_mode_seconds": -5},
        {"antispam_config": '{"threshold":10,"action":"mute","block_repeats":true,"block_links":false}'},
        {"antispam_config": '{"threshold":7,"action":"delete","block_links":1}'},
        {"antispam_config": "not json"},
        {"reactions_type": "off"},
        {"reactions_type": "some"},
        {"allowed_reactions": "👍,👎"},
        {"allowed_reactions": "a" * 501},
        {},
    ]
    themes = [
        {"wallpaper": "stars", "accent": "#1a2b3c", "dark_mode": True},
        {"wallpaper": "https://example.org/a.png"},
        {"dark_mode": False},
        {},
        {"wallpaper": "moon"},
        {"wallpaper": "http://example.org/a.png"},
        {"accent": "red"},
        {"accent": "#fff"},
    ]
    theme_cases = []
    for theme in themes:
        try:
            written = ref.room_theme(theme.get("wallpaper"), theme.get("accent"), theme.get("dark_mode"))
            theme_cases.append({"theme": theme, "written": written, "refusal": None})
        except ValueError as refusal:
            theme_cases.append({"theme": theme, "written": None, "refusal": str(refusal)})

    row = {
        "id": 7,
        "name": "General",
        "member_count": 3,
        "online_count": 1,
        "created_at_us": NOW_US + 789_012,
        "invite_code": "abcd1234",
        "creator_id": 2,
    }
    voice_row = {**row, "is_voice": True, "voice_participants": [{"user_id": 1}]}
    return {
        "settings": [{"patch": patch, "parsed": ref.room_settings(patch)} for patch in patches],
        "themes": theme_cases,
        "antispam": [
            {"payload": payload, "written": ref.room_antispam_config(payload)}
            for payload in ['{"threshold":5}', "{}", "[]", "5", "not json", '{"block_repeats":""}']
        ],
        "names": [{"text": text, "name": ref.room_name(text)} for text in ["  General  ", "", "   ", "ё" * 100, "a" * 101]],
        "replication": [
            {"text": text, "mode": ref.room_replication_mode(text)}
            for text in ["none", "federated", "None", "", "local"]
        ],
        "avatars": [{"is_voice": flag, "avatar": ref.room_avatar_given(flag)} for flag in (True, False)],
        "views": [
            {"row": row, "view": ref.room_view(**row)},
            {"row": voice_row, "view": ref.room_view(**voice_row)},
        ],
    }


def main() -> None:
    vectors = {
        "wrap": wrap_cases(),
        "wrap_stored": wrap_stored_cases(),
        "messages": message_cases(),
        "client_stamps": stamp_cases(),
        "wire_stamps": wire_stamp_cases(),
        "relay": relay_cases(),
        "room": room_cases(),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    counted = sum(len(value) for value in vectors.values() if isinstance(value, list))
    print(f"{OUT}: {counted} векторов в списках + relay/room-разделы")


if __name__ == "__main__":
    main()

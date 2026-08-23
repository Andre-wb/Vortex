"""Паритет среза 2 `vortex-proto`: Rust против замороженных векторов и против
второй независимой Python-реализации (`wire_parity_reference.py`).

Проверяется всё, что стало форматом или решением в Rust: обёртка комнатного
ключа, конверт сообщения, метки времени, формы исходящих конвертов, настройки и
представление комнаты.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.tests import wire_parity_reference as ref

vortex_chat = pytest.importorskip("vortex_chat", reason="Rust-расширение не собрано")

VECTORS = json.loads((Path(__file__).parent / "vectors" / "wire_parity.json").read_text(encoding="utf-8"))


def _wrap(payload: dict):
    return vortex_chat.wrapped_key_parse(json.dumps(payload))


# Обёртка комнатного ключа


@pytest.mark.parametrize("case", VECTORS["wrap"], ids=range(len(VECTORS["wrap"])))
def test_wrapped_key_matches_frozen_vector(case):
    parsed = _wrap(case["payload"])
    assert (parsed is not None) is case["accepted"]
    if parsed is not None:
        assert parsed.client_dict() == case["client"]


@pytest.mark.parametrize("case", VECTORS["wrap"], ids=range(len(VECTORS["wrap"])))
def test_wrapped_key_matches_the_reference(case):
    expected = ref.wrap_parse(case["payload"])
    parsed = _wrap(case["payload"])
    assert (parsed is not None) is (expected is not None)
    if parsed is not None:
        assert parsed.client_dict() == ref.wrap_client_dict(expected)


@pytest.mark.parametrize("case", VECTORS["wrap_stored"], ids=range(len(VECTORS["wrap_stored"])))
def test_stored_row_matches_frozen_vector(case):
    rendered = vortex_chat.wrapped_key_stored(
        case["ephemeral_pub"], case["ciphertext"], case["kyber_ciphertext"]
    )
    assert rendered == case["client"]
    assert rendered == ref.wrap_stored(case["ephemeral_pub"], case["ciphertext"], case["kyber_ciphertext"])


def test_a_hybrid_envelope_survives_a_round_trip_through_storage():
    payload = {
        "hybrid": True,
        "x25519_ephemeral_pub": "1a" * 32,
        "kyber_ciphertext": "3c" * 1088,
        "ciphertext": "2b" * 60,
    }
    parsed = _wrap(payload)
    stored = vortex_chat.wrapped_key_stored(parsed.ephemeral_pub, parsed.ciphertext, parsed.kyber_ciphertext)
    assert stored == parsed.client_dict()


# Конверт сообщения


def _read(case):
    return vortex_chat.message_read(json.dumps(case["frame"]), case["action"], case["now_us"])


@pytest.mark.parametrize("case", VECTORS["messages"], ids=range(len(VECTORS["messages"])))
def test_message_frame_matches_frozen_vector(case):
    parsed = _read(case)
    expected = case["parsed"]

    if expected["refusal"] is not None:
        assert parsed.refusal is not None
        assert parsed.refusal.code == expected["refusal"]
        assert parsed.refusal.message == ref.REFUSALS[expected["refusal"]]
        return

    assert parsed.refusal is None
    for field in ("ciphertext", "digest_hex", "digest_claim", "enc_v", "reply_to_id", "client_msg_id"):
        if field in expected:
            assert getattr(parsed, field) == expected[field], field
    if "mentions" in expected:
        assert list(parsed.mentions) == expected["mentions"]
    if "client_ts_us" in expected:
        assert parsed.client_ts_us == expected["client_ts_us"]
    if "thread_id" in expected:
        assert parsed.thread_id == expected["thread_id"]
    if "msg_id" in expected:
        assert parsed.msg_id == expected["msg_id"]
    if "reply_quote" in expected:
        assert parsed.reply_quote == expected["reply_quote"]


@pytest.mark.parametrize("case", VECTORS["messages"], ids=range(len(VECTORS["messages"])))
def test_message_frame_matches_the_reference(case):
    expected = ref.message_read(case["frame"], case["action"], case["now_us"])
    parsed = _read(case)
    if expected["refusal"] is not None:
        assert parsed.refusal is not None and parsed.refusal.code == expected["refusal"]
        return
    assert parsed.refusal is None
    assert parsed.ciphertext == expected.get("ciphertext", "")
    assert parsed.digest_hex == expected.get("digest_hex", "")
    assert parsed.enc_v == expected.get("enc_v")
    assert list(parsed.mentions) == expected.get("mentions", [])


def test_the_digest_is_always_the_one_the_server_computed():
    ciphertext = "ab" * 30
    honest = vortex_chat.message_read(json.dumps({"ciphertext": ciphertext}), "message", 0)
    lied = vortex_chat.message_read(
        json.dumps({"ciphertext": ciphertext, "hash": "11" * 32}), "message", 0
    )
    assert honest.digest_hex == lied.digest_hex
    assert honest.digest_claim == "absent"
    assert lied.digest_claim == "untruthful"
    truthful = vortex_chat.message_read(
        json.dumps({"ciphertext": ciphertext, "hash": honest.digest_hex}), "message", 0
    )
    assert truthful.digest_claim == "truthful"


def test_every_refusal_carries_the_frame_the_client_receives():
    parsed = vortex_chat.message_read(json.dumps({"ciphertext": "ab"}), "message", 0)
    assert parsed.refusal.frame() == {
        "type": "error",
        "message": "Ciphertext too short",
        "code": "ciphertext_short",
    }
    assert vortex_chat.message_frame_too_large() == ref.error_frame("frame_too_large")


# Метки времени


@pytest.mark.parametrize("case", VECTORS["client_stamps"], ids=range(len(VECTORS["client_stamps"])))
def test_client_stamp_matches_frozen_vector(case):
    assert vortex_chat.message_client_stamp(case["text"], case["now_us"]) == case["stamp_us"]
    assert vortex_chat.message_client_stamp(case["text"], case["now_us"]) == ref.client_stamp(
        case["text"], case["now_us"]
    )


@pytest.mark.parametrize("case", VECTORS["wire_stamps"], ids=range(len(VECTORS["wire_stamps"])))
def test_wire_stamp_matches_frozen_vector(case):
    assert vortex_chat.message_wire_stamp(case["microseconds"]) == case["wire"]
    assert vortex_chat.message_wire_stamp(case["microseconds"]) == ref.wire_stamp(case["microseconds"])


# Исходящие конверты


def test_ack_matches_frozen_vector():
    case = VECTORS["relay"]["ack"]
    assert vortex_chat.message_ack(*case["input"]) == case["payload"]
    duplicate = VECTORS["relay"]["ack_duplicate"]
    assert vortex_chat.message_ack_duplicate(*duplicate["input"]) == duplicate["payload"]


def test_sent_message_matches_frozen_vector():
    case = VECTORS["relay"]["sent"]
    assert vortex_chat.message_sent(**case["input"]) == case["payload"]
    assert vortex_chat.message_sent(**case["input"]) == ref.sent_message(**case["input"])


def test_thread_message_matches_frozen_vector():
    case = VECTORS["relay"]["thread"]
    assert vortex_chat.message_thread_sent(**case["input"]) == case["payload"]
    assert vortex_chat.message_thread_sent(**case["input"]) == ref.thread_message(**case["input"])


def test_edited_deleted_and_thread_update_match_frozen_vectors():
    edited = VECTORS["relay"]["edited"]
    deleted = VECTORS["relay"]["deleted"]
    update = VECTORS["relay"]["thread_update"]
    assert vortex_chat.message_edited(*edited["input"]) == edited["payload"]
    assert vortex_chat.message_deleted(*deleted["input"]) == deleted["payload"]
    assert vortex_chat.message_thread_update(*update["input"]) == update["payload"]


def test_stored_message_matches_frozen_vector():
    case = VECTORS["relay"]["stored"]
    fields = dict(case["input"])
    fields["content"] = bytes(fields["content"])
    fields["digest"] = bytes(fields["digest"])
    assert vortex_chat.message_stored(**fields) == case["payload"]
    assert vortex_chat.message_stored(**fields) == ref.stored_message(**fields)


def test_a_message_without_content_shows_nothing_in_its_place():
    rendered = vortex_chat.message_stored(msg_id=1, msg_type="text", created_at_us=0)
    assert rendered["ciphertext"] is None
    assert rendered["hash"] is None
    assert rendered["thread_count"] == 0
    assert rendered["is_edited"] is False


# Комната


@pytest.mark.parametrize("case", VECTORS["room"]["settings"], ids=range(len(VECTORS["room"]["settings"])))
def test_room_settings_match_frozen_vector(case):
    parsed = vortex_chat.room_settings_parse(json.dumps(case["patch"]))
    expected = case["parsed"]
    assert parsed.refusal == expected["refusal"]
    if expected["refusal"] is not None:
        return
    for field in (
        "name",
        "description",
        "avatar_emoji",
        "slow_mode_seconds",
        "reactions_type",
        "allowed_reactions",
        "antispam_config",
    ):
        if field in expected:
            assert getattr(parsed, field) == expected[field], field
    if "auto_delete_given" in expected:
        assert parsed.auto_delete_given is expected["auto_delete_given"]
        assert parsed.auto_delete_seconds == expected["auto_delete_seconds"]
    if "antispam_config_refused" in expected:
        assert parsed.antispam_config_refused is expected["antispam_config_refused"]


@pytest.mark.parametrize("case", VECTORS["room"]["themes"], ids=range(len(VECTORS["room"]["themes"])))
def test_room_theme_matches_frozen_vector(case):
    theme = case["theme"]
    if case["refusal"] is None:
        written = vortex_chat.room_theme(theme.get("wallpaper"), theme.get("accent"), theme.get("dark_mode"))
        assert written == case["written"]
        assert json.loads(written) == json.loads(
            ref.room_theme(theme.get("wallpaper"), theme.get("accent"), theme.get("dark_mode"))
        )
        return
    with pytest.raises(ValueError) as refused:
        vortex_chat.room_theme(theme.get("wallpaper"), theme.get("accent"), theme.get("dark_mode"))
    assert str(refused.value) == case["refusal"]


@pytest.mark.parametrize("case", VECTORS["room"]["antispam"], ids=range(len(VECTORS["room"]["antispam"])))
def test_room_antispam_config_matches_frozen_vector(case):
    assert vortex_chat.room_antispam_config(case["payload"]) == case["written"]
    assert vortex_chat.room_antispam_config(case["payload"]) == ref.room_antispam_config(case["payload"])


@pytest.mark.parametrize("case", VECTORS["room"]["names"], ids=range(len(VECTORS["room"]["names"])))
def test_room_name_matches_frozen_vector(case):
    assert vortex_chat.room_name_read(case["text"]) == case["name"]
    assert vortex_chat.room_name_read(case["text"]) == ref.room_name(case["text"])


@pytest.mark.parametrize("case", VECTORS["room"]["replication"], ids=range(len(VECTORS["room"]["replication"])))
def test_room_replication_mode_matches_frozen_vector(case):
    assert vortex_chat.room_replication_mode(case["text"]) == case["mode"]


@pytest.mark.parametrize("case", VECTORS["room"]["avatars"], ids=range(len(VECTORS["room"]["avatars"])))
def test_room_avatar_matches_frozen_vector(case):
    assert vortex_chat.room_avatar_given(case["is_voice"]) == case["avatar"]


@pytest.mark.parametrize("case", VECTORS["room"]["views"], ids=range(len(VECTORS["room"]["views"])))
def test_room_view_matches_frozen_vector(case):
    rendered = vortex_chat.room_view(**case["row"])
    assert rendered == case["view"]
    assert rendered == ref.room_view(**case["row"])

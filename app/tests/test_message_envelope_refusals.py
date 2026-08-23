"""Отказы конверта сообщения на живом WebSocket.

Решение владельца (срез 2 `vortex-proto`): любой отказ разбора кадра — один и тот
же ответ `{type: "error", message, code}`, включая `edit_message`, который прежде
молчал, и пустой шифротекст, на котором молчала отправка.
"""

import secrets

from conftest import _phone_prefix, random_digits, random_str
from starlette.testclient import TestClient

from app.main import app


def _recv_error(ws, limit=15):
    for _ in range(limit):
        frame = ws.receive_json()
        if frame.get("type") == "error":
            return frame
    raise AssertionError("Не дождались кадра ошибки")


def _setup(tc):
    tag = random_str(8)
    phone = f"+3{int(_phone_prefix, 16):04d}{random_digits(7)}"
    tc.post(
        "/api/authentication/register",
        json={
            "username": f"env_{tag}",
            "password": "Str0ng_abcd!@",
            "display_name": f"Env {tag}",
            "phone": phone,
            "avatar_emoji": "\U0001f512",
            "x25519_public_key": secrets.token_hex(32),
        },
    )
    csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
    tc.post(
        "/api/authentication/login",
        json={"phone_or_username": f"env_{tag}", "password": "Str0ng_abcd!@"},
        headers={"X-CSRF-Token": csrf},
    )
    room = tc.post(
        "/api/rooms",
        json={
            "name": f"envroom_{tag}",
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        },
        headers={"X-CSRF-Token": csrf},
    )
    return room.json().get("id")


class TestEnvelopeRefusals:
    def test_every_kind_of_bad_ciphertext_is_answered(self):
        cases = [
            ({"action": "message"}, "ciphertext_required"),
            ({"action": "message", "ciphertext": "   "}, "ciphertext_required"),
            ({"action": "message", "ciphertext": "ab" * 20}, "ciphertext_short"),
            ({"action": "message", "ciphertext": "zz" * 30}, "ciphertext_hex"),
        ]
        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id = _setup(tc)
            for payload, code in cases:
                with tc.websocket_connect(f"/ws/{room_id}") as ws:
                    ws.send_json(payload)
                    frame = _recv_error(ws)
                assert frame["code"] == code, payload

    def test_an_edit_no_longer_fails_silently(self):
        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id = _setup(tc)
            with tc.websocket_connect(f"/ws/{room_id}") as ws:
                ws.send_json({"action": "edit_message", "msg_id": 1, "ciphertext": "abcd"})
                frame = _recv_error(ws)
            assert frame["type"] == "error"
            assert frame["message"] == "Ciphertext too short"
            assert frame["code"] == "ciphertext_short"

    def test_an_edit_without_a_message_is_answered(self):
        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id = _setup(tc)
            with tc.websocket_connect(f"/ws/{room_id}") as ws:
                ws.send_json({"action": "edit_message", "ciphertext": "ab" * 30})
                frame = _recv_error(ws)
            assert frame["code"] == "message_id_required"

    def test_a_thread_reply_without_a_thread_is_answered(self):
        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id = _setup(tc)
            with tc.websocket_connect(f"/ws/{room_id}") as ws:
                ws.send_json({"action": "thread_reply", "ciphertext": "ab" * 30})
                frame = _recv_error(ws)
            assert frame["code"] == "thread_id_required"

    def test_a_deletion_without_a_message_is_answered(self):
        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id = _setup(tc)
            with tc.websocket_connect(f"/ws/{room_id}") as ws:
                ws.send_json({"action": "delete_message"})
                frame = _recv_error(ws)
            assert frame["code"] == "message_id_required"

    def test_a_frame_larger_than_the_cap_is_answered(self):
        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id = _setup(tc)
            with tc.websocket_connect(f"/ws/{room_id}") as ws:
                ws.send_json({"action": "message", "ciphertext": "ab" * 40000})
                frame = _recv_error(ws)
            assert frame["code"] == "frame_too_large"

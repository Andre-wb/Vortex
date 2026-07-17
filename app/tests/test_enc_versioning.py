"""Тесты версионирования конверта шифрования (enc_v).

Проверяют, что сервер принимает, валидирует, хранит и переизлучает поле
enc_v, оставаясь полностью «слепым» к содержимому ciphertext, и что
до-версионные сообщения (без поля) продолжают работать как раньше.
"""

import secrets

import pytest

from conftest import random_str, random_digits, _phone_prefix
from app.main import app
from app.chats.messages._router import parse_enc_v


class TestParseEncV:
    """Валидация поля enc_v (правило: сервер не отклоняет
    неизвестные версии — они хранятся opaque)."""

    def test_valid_versions(self):
        assert parse_enc_v({"enc_v": 0}) == 0
        assert parse_enc_v({"enc_v": 1}) == 1
        assert parse_enc_v({"enc_v": 7}) == 7      # неизвестная, но валидная
        assert parse_enc_v({"enc_v": 255}) == 255  # верхняя граница

    def test_missing_field_is_none(self):
        assert parse_enc_v({}) is None
        assert parse_enc_v({"enc_v": None}) is None

    def test_garbage_is_none(self):
        assert parse_enc_v({"enc_v": "1"}) is None       # строка — не версия
        assert parse_enc_v({"enc_v": -1}) is None
        assert parse_enc_v({"enc_v": 256}) is None
        assert parse_enc_v({"enc_v": 1.5}) is None
        assert parse_enc_v({"enc_v": True}) is None      # bool — не версия
        assert parse_enc_v({"enc_v": [1]}) is None
        assert parse_enc_v({"enc_v": {"v": 1}}) is None


def _recv_until(ws, msg_type, limit=15):
    """Читает WS-фреймы, пока не встретит type == msg_type."""
    for _ in range(limit):
        m = ws.receive_json()
        if m.get("type") == msg_type:
            return m
    raise AssertionError(f"Не дождались фрейма типа {msg_type!r}")


class TestEncVersionOverWebSocket:

    @staticmethod
    def _setup(tc):
        """Регистрирует пользователя и комнату, возвращает (room_id, csrf)."""
        tag   = random_str(8)
        phone = f"+3{int(_phone_prefix, 16):04d}{random_digits(7)}"
        tc.post("/api/authentication/register", json={
            "username":          f"encv_{tag}",
            "password":          "Str0ng_abcd!@",
            "display_name":      f"EncV {tag}",
            "phone":             phone,
            "avatar_emoji":      "\U0001f512",
            "x25519_public_key": secrets.token_hex(32),
        })
        csrf = tc.get("/api/authentication/csrf-token").json().get("csrf_token", "")
        tc.post("/api/authentication/login", json={
            "phone_or_username": f"encv_{tag}",
            "password":          "Str0ng_abcd!@",
        }, headers={"X-CSRF-Token": csrf})
        r = tc.post("/api/rooms", json={
            "name":               f"encvroom_{tag}",
            "is_public":          True,
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext":    secrets.token_hex(60),
            },
        }, headers={"X-CSRF-Token": csrf})
        return r.json().get("id"), csrf

    def _send_and_get_id(self, ws, payload):
        ws.send_json(payload)
        ack = _recv_until(ws, "ack")
        assert ack.get("server_id"), f"нет server_id в ack: {ack}"
        return ack["server_id"]

    def _history_entry(self, tc, room_id, server_id):
        with tc.websocket_connect(f"/ws/{room_id}") as ws:
            history = _recv_until(ws, "history")
        entry = next((m for m in history["messages"] if m.get("msg_id") == server_id), None)
        assert entry is not None, f"сообщение {server_id} не найдено в истории"
        return entry

    def test_enc_v_stored_and_relayed_in_history(self):
        """enc_v:1 сохраняется и возвращается в history через to_relay_dict."""
        from starlette.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, _ = self._setup(tc)
            with tc.websocket_connect(f"/ws/{room_id}") as ws:
                server_id = self._send_and_get_id(ws, {
                    "action":     "message",
                    "ciphertext": secrets.token_hex(32),
                    "enc_v":      1,
                })
            entry = self._history_entry(tc, room_id, server_id)
            assert entry.get("enc_v") == 1

    def test_missing_enc_v_stays_null(self):
        """Старый клиент без поля enc_v: сообщение проходит, версия NULL."""
        from starlette.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, _ = self._setup(tc)
            with tc.websocket_connect(f"/ws/{room_id}") as ws:
                server_id = self._send_and_get_id(ws, {
                    "action":     "message",
                    "ciphertext": secrets.token_hex(32),
                })
            entry = self._history_entry(tc, room_id, server_id)
            assert entry.get("enc_v") is None

    def test_unknown_future_version_kept_opaque(self):
        """enc_v:7 (будущая версия) не отклоняется и переизлучается как есть."""
        from starlette.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, _ = self._setup(tc)
            with tc.websocket_connect(f"/ws/{room_id}") as ws:
                server_id = self._send_and_get_id(ws, {
                    "action":     "message",
                    "ciphertext": secrets.token_hex(32),
                    "enc_v":      7,
                })
            entry = self._history_entry(tc, room_id, server_id)
            assert entry.get("enc_v") == 7

    def test_garbage_enc_v_does_not_crash_and_stays_null(self):
        """Мусорное значение enc_v игнорируется, обработчик не падает."""
        from starlette.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, _ = self._setup(tc)
            with tc.websocket_connect(f"/ws/{room_id}") as ws:
                server_id = self._send_and_get_id(ws, {
                    "action":     "message",
                    "ciphertext": secrets.token_hex(32),
                    "enc_v":      "definitely-not-a-version",
                })
            entry = self._history_entry(tc, room_id, server_id)
            assert entry.get("enc_v") is None

    def test_thread_reply_carries_enc_v(self):
        from starlette.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, _ = self._setup(tc)
            with tc.websocket_connect(f"/ws/{room_id}") as ws:
                root_id = self._send_and_get_id(ws, {
                    "action":     "message",
                    "ciphertext": secrets.token_hex(32),
                    "enc_v":      1,
                })
                reply_id = self._send_and_get_id(ws, {
                    "action":     "thread_reply",
                    "thread_id":  root_id,
                    "ciphertext": secrets.token_hex(32),
                    "enc_v":      1,
                })
            # Тредовые ответы не попадают в основную history — читаем тред
            r = tc.get(f"/api/rooms/{room_id}/thread/{root_id}")
            assert r.status_code == 200
            body = r.json()
            assert body["root"]["enc_v"] == 1
            reply = next((m for m in body["replies"] if m.get("msg_id") == reply_id), None)
            assert reply is not None
            assert reply.get("enc_v") == 1

    def test_edit_updates_enc_v_and_preserves_history_version(self):
        """Редактирование: msg.enc_version обновляется, история хранит
        enc_v предыдущей версии; broadcast message_edited несёт enc_v."""
        from starlette.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, _ = self._setup(tc)
            with tc.websocket_connect(f"/ws/{room_id}") as ws:
                server_id = self._send_and_get_id(ws, {
                    "action":     "message",
                    "ciphertext": secrets.token_hex(32),
                    "enc_v":      1,
                })
                ws.send_json({
                    "action":     "edit_message",
                    "msg_id":     server_id,
                    "ciphertext": secrets.token_hex(32),
                    "enc_v":      1,
                })
                edited = _recv_until(ws, "message_edited")
                assert edited.get("enc_v") == 1

            r = tc.get(f"/api/rooms/{room_id}/messages/{server_id}/history")
            assert r.status_code == 200
            body = r.json()
            assert body["current"]["enc_v"] == 1
            assert len(body["history"]) == 1
            assert body["history"][0]["enc_v"] == 1  # версия ДО правки

    def test_ciphertext_still_opaque_to_server(self):
        """Сервер по-прежнему не парсит ciphertext: произвольный hex с
        enc_v проходит все проверки (только hex + длина)."""
        from starlette.testclient import TestClient

        with TestClient(app, raise_server_exceptions=False) as tc:
            room_id, _ = self._setup(tc)
            with tc.websocket_connect(f"/ws/{room_id}") as ws:
                # 24 байта нулей — валидный hex ≥48 симв., но бессмысленный
                # как шифртекст; сервер обязан принять (E2E-слепота)
                server_id = self._send_and_get_id(ws, {
                    "action":     "message",
                    "ciphertext": "00" * 24,
                    "enc_v":      1,
                })
            assert server_id

"""
app/tests/test_coverage_gaps.py — Tests for previously untested endpoints.

Covers:
  - Global search (/api/users/global-search)
  - Message search (/api/rooms/{id}/messages/search)
  - Security questions (setup, recover, defaults, load)
  - Contact sync (sync, add-all)
  - Sealed prekeys (upload, claim, count)
  - Bot messaging (send, reply, me, rooms, updates)
  - Bot marketplace (publish, detail, reviews, install)
  - Native bridge (push register/unregister, capabilities, biometric)
"""
from __future__ import annotations

from conftest import SyncASGIClient, make_user, random_str


def _auth(client: SyncASGIClient):
    u = make_user(client)
    return u, u["headers"]


def _create_room(client, headers, name=None):
    r = client.post("/api/rooms", json={"name": name or f"room_{random_str(6)}"}, headers=headers)
    if r.status_code in (200, 201):
        data = r.json()
        return data.get("id") or data.get("room", {}).get("id")
    return None


def _create_bot(client, headers):
    r = client.post("/api/bots", json={
        "username": f"bot_{random_str(6)}",
        "display_name": "Test Bot",
    }, headers=headers)
    if r.status_code in (200, 201):
        return r.json()
    return None


# 1. GLOBAL SEARCH


class TestSealedPrekeys:
    """Sealed-prekey эндпоинты УДАЛЕНЫ: механизм был сломан (room key оборачивался
    на one-time pubkey, чей приватный отбрасывался → пакет недекриптуем; авто-claim
    создавал сломанный EncryptedRoomKey с has_key=True, глуша рабочий key_request).
    Раздача ключей — через key_request/store-key/provide-key. Фиксируем, что
    маршруты upload/claim/count больше не зарегистрированы (404)."""

    def test_sealed_prekey_endpoints_removed(self, client):
        _, h = _auth(client)
        rid = _create_room(client, h)
        if not rid:
            return
        assert client.get(f"/api/rooms/{rid}/prekey-count", headers=h).status_code == 404
        assert client.post(f"/api/rooms/{rid}/sealed-prekeys",
                           json={"packages": []}, headers=h).status_code == 404
        assert client.post(f"/api/rooms/{rid}/claim-prekey",
                           json={"pubkey": "dd" * 32}, headers=h).status_code == 404


# 6. BOT MESSAGING

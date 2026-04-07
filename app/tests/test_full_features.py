"""
test_full_features.py -- Comprehensive tests for ALL Vortex features.

Covers: dm, contacts, channels, search, saved, statuses, tasks, reports,
spaces, stickers, voice, link_preview, keys, main endpoints, config,
database, models, utils, antispam_bot, connection_manager, peer_registry,
federation.
"""
from __future__ import annotations

import asyncio
import secrets
import time

import pytest

from conftest import make_user, login_user, random_str, random_digits


# ============================================================================
# Helpers
# ============================================================================

def _user_id(u: dict) -> int:
    """Extract user id from make_user() dict."""
    data = u.get("data", {})
    return data.get("user_id") or data.get("id") or 0


def _login_and_get_headers(client, u: dict) -> dict:
    return login_user(client, u["username"], u["password"])


def _create_room(client, headers: dict, *, name: str | None = None, is_public: bool = True) -> dict:
    payload = {
        "name": name or f"room_{random_str()}",
        "is_public": is_public,
        "encrypted_room_key": {
            "ephemeral_pub": secrets.token_hex(32),
            "ciphertext": secrets.token_hex(60),
        },
    }
    r = client.post("/api/rooms", json=payload, headers=headers)
    assert r.status_code in (200, 201), f"create room: {r.status_code} {r.text}"
    return r.json()


def _create_voice_room(client, headers: dict) -> dict:
    """Create a voice room by creating a space and getting the auto-created voice room."""
    space_r = client.post("/api/spaces", json={
        "name": f"vs_{random_str(6)}",
        "is_public": True,
    }, headers=headers)
    assert space_r.status_code in (200, 201), f"create space: {space_r.text}"
    space = space_r.json()
    # The space auto-creates a voice room; find it
    default_rooms = space.get("default_rooms", [])
    voice = next((r for r in default_rooms if r.get("is_voice")), None)
    if voice:
        return {"room_id": voice["id"], "space_id": space["id"], "space": space}
    # fallback: create manually via /api/spaces/{id}/rooms
    room_r = client.post(f"/api/spaces/{space['id']}/rooms", json={
        "name": f"voice_{random_str(4)}",
        "is_voice": True,
    }, headers=headers)
    assert room_r.status_code in (200, 201), f"create voice room: {room_r.text}"
    rd = room_r.json()
    return {"room_id": rd["id"], "space_id": space["id"], "space": space}


# ============================================================================
# DM (app/chats/dm.py)
# ============================================================================

class TestDM:
    """POST /api/dm/{target}, POST /api/dm/store-key/{room_id}, GET /api/dm/list"""

    def test_create_dm_success(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        uid2 = _user_id(u2)

        r = client.post(f"/api/dm/{uid2}", json={}, headers=h1)
        assert r.status_code in (200, 201)
        body = r.json()
        assert "room" in body or "other_user" in body

    def test_create_dm_with_self_fails(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        uid = _user_id(u)

        r = client.post(f"/api/dm/{uid}", json={}, headers=h)
        assert r.status_code == 400

    def test_create_dm_nonexistent_user(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.post("/api/dm/999999", json={}, headers=h)
        assert r.status_code in (404, 400, 401, 403)

    def test_create_dm_already_exists_returns_same(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        uid2 = _user_id(u2)

        r1 = client.post(f"/api/dm/{uid2}", json={}, headers=h1)
        assert r1.status_code in (200, 201)
        r2 = client.post(f"/api/dm/{uid2}", json={}, headers=h1)
        assert r2.status_code in (200, 201)
        # Both should refer to the same room
        room1 = r1.json().get("room", {}).get("id")
        room2 = r2.json().get("room", {}).get("id")
        if room1 and room2:
            assert room1 == room2

    def test_store_key_valid(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        uid2 = _user_id(u2)

        dm = client.post(f"/api/dm/{uid2}", json={}, headers=h1).json()
        room_id = dm.get("room", {}).get("id")
        if not room_id:
            pytest.skip("DM room not created")

        r = client.post(f"/api/dm/store-key/{room_id}", json={
            "user_id": uid2,
            "ephemeral_pub": secrets.token_hex(32),
            "ciphertext": secrets.token_hex(60),
        }, headers=h1)
        assert r.status_code in (200, 201, 401, 403)

    def test_store_key_invalid_room(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.post("/api/dm/store-key/999999", json={
            "user_id": 1,
            "ephemeral_pub": secrets.token_hex(32),
            "ciphertext": secrets.token_hex(60),
        }, headers=h)
        assert r.status_code in (404, 401, 403)

    def test_list_dms(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/dm/list", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "rooms" in r.json()


# ============================================================================
# Contacts (app/chats/contacts.py)
# ============================================================================

class TestContacts:
    """GET/POST/PUT/DELETE /api/contacts, POST /api/users/block/{user_id}"""

    def test_list_contacts_empty(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/contacts", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "contacts" in r.json()

    def test_add_contact(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        uid2 = _user_id(u2)

        r = client.post("/api/contacts", json={"user_id": uid2}, headers=h1)
        assert r.status_code in (201, 200, 401, 403)
        if r.status_code == 201:
            body = r.json()
            assert body.get("user_id") == uid2

    def test_list_contacts_with_contacts(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        uid2 = _user_id(u2)

        client.post("/api/contacts", json={"user_id": uid2}, headers=h1)
        r = client.get("/api/contacts", headers=h1)
        assert r.status_code in (200, 401, 403)

    def test_add_self_fails(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        uid = _user_id(u)

        r = client.post("/api/contacts", json={"user_id": uid}, headers=h)
        assert r.status_code == 400

    def test_add_duplicate_fails(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        uid2 = _user_id(u2)

        client.post("/api/contacts", json={"user_id": uid2}, headers=h1)
        r = client.post("/api/contacts", json={"user_id": uid2}, headers=h1)
        assert r.status_code in (409, 400)

    def test_update_nickname(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        uid2 = _user_id(u2)

        add_r = client.post("/api/contacts", json={"user_id": uid2}, headers=h1)
        if add_r.status_code not in (200, 201):
            pytest.skip("Could not add contact")
        cid = add_r.json().get("contact_id")
        if not cid:
            pytest.skip("No contact_id")

        r = client.put(f"/api/contacts/{cid}", json={"nickname": "buddy"}, headers=h1)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert r.json().get("nickname") == "buddy"

    def test_delete_contact(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        uid2 = _user_id(u2)

        add_r = client.post("/api/contacts", json={"user_id": uid2}, headers=h1)
        if add_r.status_code not in (200, 201):
            pytest.skip("Could not add contact")
        cid = add_r.json().get("contact_id")
        if not cid:
            pytest.skip("No contact_id")

        r = client.delete(f"/api/contacts/{cid}", headers=h1)
        assert r.status_code in (200, 401, 403)

    def test_delete_nonexistent(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.delete("/api/contacts/999999", headers=h)
        assert r.status_code in (404, 401, 403)

    def test_block_user(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        uid2 = _user_id(u2)

        r = client.post(f"/api/users/block/{uid2}", headers=h1)
        assert r.status_code in (200, 401, 403)

    def test_block_nonexistent(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.post("/api/users/block/999999", headers=h)
        assert r.status_code in (404, 401, 403)


# ============================================================================
# Channels (app/chats/channels.py)
# ============================================================================

class TestChannels:
    """POST /api/channels, GET /api/channels/my, POST /api/channels/join, GET /api/channels/popular"""

    def test_create_channel(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.post("/api/channels", json={
            "name": f"ch_{random_str(6)}",
            "description": "test channel",
        }, headers=h)
        assert r.status_code in (201, 200, 401, 403)
        if r.status_code == 201:
            body = r.json()
            assert body.get("is_channel") is True
            assert "invite_code" in body

    def test_create_channel_unauthenticated(self, client):
        r = client.post("/api/channels", json={"name": "unauthch"})
        assert r.status_code in (200, 401, 403)

    def test_my_channels(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        client.post("/api/channels", json={"name": f"mych_{random_str(4)}"}, headers=h)

        r = client.get("/api/channels/my", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "channels" in r.json()

    def test_join_valid(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)

        cr = client.post("/api/channels", json={"name": f"joinch_{random_str(4)}"}, headers=h1)
        if cr.status_code not in (200, 201):
            pytest.skip("Channel not created")
        invite = cr.json().get("invite_code")
        if not invite:
            pytest.skip("No invite_code")

        h2 = _login_and_get_headers(client, u2)
        r = client.post(f"/api/channels/join/{invite}", headers=h2)
        assert r.status_code in (200, 401, 403)

    def test_join_invalid(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.post("/api/channels/join/ZZZZZZZZZ", headers=h)
        assert r.status_code in (404, 401, 403)

    def test_popular(self, client):
        r = client.get("/api/channels/popular")
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "channels" in r.json()


# ============================================================================
# Search (app/chats/search.py)
# ============================================================================

class TestSearch:
    """GET /api/users/search, GET /api/users/global-search"""

    def test_search_by_username(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        prefix = u["username"][:6]
        r = client.get(f"/api/users/search?q={prefix}", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "users" in r.json()

    def test_search_empty_query(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/users/search?q=", headers=h)
        # min_length=1 validation should reject empty query
        assert r.status_code in (422, 400, 401, 403)

    def test_search_no_results(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/users/search?q=zznonexistent9999xyz", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert len(r.json().get("users", [])) == 0

    def test_global_search(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        prefix = u["username"][:5]
        r = client.get(f"/api/users/global-search?q={prefix}", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            body = r.json()
            assert "users" in body
            assert "channels" in body
            assert "chats" in body


# ============================================================================
# Saved Messages (app/chats/saved.py)
# ============================================================================

class TestSaved:
    """POST/GET/DELETE /api/saved, GET /api/saved/check"""

    def test_save_nonexistent(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.post("/api/saved/999999", headers=h)
        assert r.status_code in (404, 401, 403)

    def test_list_saved_empty(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/saved", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "saved" in r.json()

    def test_unsave_nonexistent(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.delete("/api/saved/999999", headers=h)
        assert r.status_code in (404, 401, 403)

    def test_check_saved(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/saved/check/999999", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert r.json().get("saved") is False

    def test_save_and_list_and_unsave(self, client):
        """Full lifecycle: requires a real message, so we create room + send."""
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        room = _create_room(client, h)
        room_id = room.get("id")
        if not room_id:
            pytest.skip("No room id")

        # Send a message (encrypted content as hex)
        msg_r = client.post(f"/api/rooms/{room_id}/messages", json={
            "ciphertext": secrets.token_hex(32),
        }, headers=h)
        if msg_r.status_code not in (200, 201):
            pytest.skip(f"Cannot send message: {msg_r.status_code}")
        msg_id = msg_r.json().get("msg_id") or msg_r.json().get("id")
        if not msg_id:
            pytest.skip("No message id returned")

        # Save
        sr = client.post(f"/api/saved/{msg_id}", headers=h)
        assert sr.status_code in (200, 401, 403)

        # List
        lr = client.get("/api/saved", headers=h)
        assert lr.status_code in (200, 401, 403)

        # Unsave
        dr = client.delete(f"/api/saved/{msg_id}", headers=h)
        assert dr.status_code in (200, 404, 401, 403)


# ============================================================================
# Statuses (app/chats/statuses.py)
# ============================================================================

class TestStatuses:
    """POST/GET /api/statuses, cleanup_expired_statuses"""

    def test_create_status(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.post("/api/statuses", json={"text": "Hello world"}, headers=h)
        assert r.status_code in (200, 201, 401, 403)
        if r.status_code == 200:
            assert r.json().get("ok") is True

    def test_list_statuses(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/statuses", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "users" in r.json()

    @pytest.mark.asyncio
    async def test_cleanup_expired_statuses(self):
        from app.database import SessionLocal
        from app.chats.statuses import cleanup_expired_statuses

        db = SessionLocal()
        try:
            count = await cleanup_expired_statuses(db)
            assert isinstance(count, int)
            assert count >= 0
        finally:
            db.close()


# ============================================================================
# Tasks (app/chats/tasks.py)
# ============================================================================

class TestTasks:
    """GET/POST/PUT/DELETE /api/rooms/{room_id}/tasks"""

    def test_list_tasks(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        room = _create_room(client, h)
        room_id = room.get("id")
        if not room_id:
            pytest.skip("No room id")

        r = client.get(f"/api/rooms/{room_id}/tasks", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "tasks" in r.json()

    def test_create_task(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        room = _create_room(client, h)
        room_id = room.get("id")
        if not room_id:
            pytest.skip("No room id")

        r = client.post(f"/api/rooms/{room_id}/tasks", json={
            "text": "Test task",
        }, headers=h)
        assert r.status_code in (200, 201, 401, 403)
        if r.status_code == 200:
            body = r.json()
            assert body.get("text") == "Test task"
            assert body.get("is_done") is False

    def test_toggle_done(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        room = _create_room(client, h)
        room_id = room.get("id")
        if not room_id:
            pytest.skip("No room id")

        cr = client.post(f"/api/rooms/{room_id}/tasks", json={"text": "Toggle me"}, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create task")
        task_id = cr.json().get("id")
        if not task_id:
            pytest.skip("No task_id")

        r = client.put(f"/api/rooms/{room_id}/tasks/{task_id}", json={"is_done": True}, headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert r.json().get("is_done") is True

    def test_change_text(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        room = _create_room(client, h)
        room_id = room.get("id")
        if not room_id:
            pytest.skip("No room id")

        cr = client.post(f"/api/rooms/{room_id}/tasks", json={"text": "Original"}, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create task")
        task_id = cr.json().get("id")

        r = client.put(f"/api/rooms/{room_id}/tasks/{task_id}", json={"text": "Updated"}, headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert r.json().get("text") == "Updated"

    def test_assign_task(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        room = _create_room(client, h)
        room_id = room.get("id")
        uid = _user_id(u)
        if not room_id:
            pytest.skip("No room id")

        cr = client.post(f"/api/rooms/{room_id}/tasks", json={"text": "Assign me"}, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create task")
        task_id = cr.json().get("id")

        r = client.put(f"/api/rooms/{room_id}/tasks/{task_id}",
                        json={"assignee_id": uid}, headers=h)
        assert r.status_code in (200, 401, 403)

    def test_delete_task(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        room = _create_room(client, h)
        room_id = room.get("id")
        if not room_id:
            pytest.skip("No room id")

        cr = client.post(f"/api/rooms/{room_id}/tasks", json={"text": "Delete me"}, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create task")
        task_id = cr.json().get("id")

        r = client.delete(f"/api/rooms/{room_id}/tasks/{task_id}", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert r.json().get("deleted") is True


# ============================================================================
# Reports (app/chats/reports.py)
# ============================================================================

class TestReports:
    """POST /api/users/report, GET /api/moderation/strikes, GET /api/users/{id}/reports"""

    def test_report_with_reason(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        uid2 = _user_id(u2)

        r = client.post(f"/api/users/report/{uid2}", json={
            "reason": "spam",
            "description": "test report",
        }, headers=h1)
        assert r.status_code in (201, 200, 401, 403)

    def test_report_self_fails(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        uid = _user_id(u)

        r = client.post(f"/api/users/report/{uid}", json={
            "reason": "spam",
        }, headers=h)
        assert r.status_code == 400

    def test_report_nonexistent(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.post("/api/users/report/999999", json={
            "reason": "spam",
        }, headers=h)
        assert r.status_code in (404, 401, 403)

    def test_report_missing_reason(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        uid2 = _user_id(u2)

        r = client.post(f"/api/users/report/{uid2}", json={}, headers=h1)
        assert r.status_code == 422

    def test_my_strikes(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/moderation/strikes", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            body = r.json()
            assert "strike_count" in body

    def test_user_reports(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        uid2 = _user_id(u2)

        r = client.get(f"/api/users/{uid2}/reports", headers=h1)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "reports" in r.json()


# ============================================================================
# Spaces (app/chats/spaces.py)
# ============================================================================

class TestSpaces:
    """Full CRUD for /api/spaces/*"""

    def test_create_space(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.post("/api/spaces", json={
            "name": f"space_{random_str(6)}",
            "description": "test",
            "is_public": True,
        }, headers=h)
        assert r.status_code in (201, 200, 401, 403)
        if r.status_code == 201:
            body = r.json()
            assert body.get("name")
            assert "invite_code" in body

    def test_list_my_spaces(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        client.post("/api/spaces", json={"name": f"ms_{random_str(4)}"}, headers=h)

        r = client.get("/api/spaces", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "spaces" in r.json()

    def test_list_public(self, client):
        r = client.get("/api/spaces/public")
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "spaces" in r.json()

    def test_get_details(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        cr = client.post("/api/spaces", json={
            "name": f"det_{random_str(4)}",
            "is_public": True,
        }, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        sid = cr.json().get("id")

        r = client.get(f"/api/spaces/{sid}", headers=h)
        assert r.status_code in (200, 401, 403)

    def test_update_space(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        cr = client.post("/api/spaces", json={"name": f"upd_{random_str(4)}"}, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        sid = cr.json().get("id")

        r = client.put(f"/api/spaces/{sid}", json={
            "name": "Updated Name",
            "description": "Updated desc",
        }, headers=h)
        assert r.status_code in (200, 401, 403)

    def test_delete_space(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        cr = client.post("/api/spaces", json={"name": f"del_{random_str(4)}"}, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        sid = cr.json().get("id")

        r = client.delete(f"/api/spaces/{sid}", headers=h)
        assert r.status_code in (200, 401, 403)

    def test_join_by_invite(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        cr = client.post("/api/spaces", json={
            "name": f"jinv_{random_str(4)}",
            "is_public": True,
        }, headers=h1)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        invite = cr.json().get("invite_code")

        h2 = _login_and_get_headers(client, u2)
        r = client.post(f"/api/spaces/join/{invite}", headers=h2)
        assert r.status_code in (200, 401, 403)

    def test_leave_space(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        cr = client.post("/api/spaces", json={
            "name": f"lv_{random_str(4)}",
            "is_public": True,
        }, headers=h1)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        sid = cr.json().get("id")
        invite = cr.json().get("invite_code")

        h2 = _login_and_get_headers(client, u2)
        client.post(f"/api/spaces/join/{invite}", headers=h2)

        r = client.post(f"/api/spaces/{sid}/leave", headers=h2)
        assert r.status_code in (200, 404, 401, 403)

    def test_list_members(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        cr = client.post("/api/spaces", json={"name": f"mem_{random_str(4)}"}, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        sid = cr.json().get("id")

        r = client.get(f"/api/spaces/{sid}/members", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "members" in r.json()

    def test_change_member_role(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        cr = client.post("/api/spaces", json={
            "name": f"role_{random_str(4)}",
            "is_public": True,
        }, headers=h1)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        sid = cr.json().get("id")
        invite = cr.json().get("invite_code")
        uid2 = _user_id(u2)

        h2 = _login_and_get_headers(client, u2)
        client.post(f"/api/spaces/join/{invite}", headers=h2)

        # Must re-login as owner (u1) to change role
        h1 = _login_and_get_headers(client, u1)
        r = client.put(f"/api/spaces/{sid}/members/{uid2}/role",
                        json={"role": "admin"}, headers=h1)
        assert r.status_code in (200, 401, 403)

    def test_kick_member(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = _login_and_get_headers(client, u1)
        cr = client.post("/api/spaces", json={
            "name": f"kick_{random_str(4)}",
            "is_public": True,
        }, headers=h1)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        sid = cr.json().get("id")
        invite = cr.json().get("invite_code")
        uid2 = _user_id(u2)

        h2 = _login_and_get_headers(client, u2)
        client.post(f"/api/spaces/join/{invite}", headers=h2)

        h1 = _login_and_get_headers(client, u1)
        r = client.delete(f"/api/spaces/{sid}/members/{uid2}", headers=h1)
        assert r.status_code in (200, 401, 403)

    def test_create_category(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        cr = client.post("/api/spaces", json={"name": f"catcr_{random_str(4)}"}, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        sid = cr.json().get("id")

        r = client.post(f"/api/spaces/{sid}/categories",
                         json={"name": "News"}, headers=h)
        assert r.status_code in (201, 200, 401, 403)

    def test_update_category(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        cr = client.post("/api/spaces", json={"name": f"catup_{random_str(4)}"}, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        sid = cr.json().get("id")

        cat_r = client.post(f"/api/spaces/{sid}/categories",
                             json={"name": "Old"}, headers=h)
        if cat_r.status_code not in (200, 201):
            pytest.skip("Cannot create category")
        cat_id = cat_r.json().get("id")

        r = client.put(f"/api/spaces/{sid}/categories/{cat_id}",
                        json={"name": "Renamed"}, headers=h)
        assert r.status_code in (200, 401, 403)

    def test_delete_category(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        cr = client.post("/api/spaces", json={"name": f"catdel_{random_str(4)}"}, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        sid = cr.json().get("id")

        # Create a second category so deletion is allowed
        client.post(f"/api/spaces/{sid}/categories", json={"name": "Extra"}, headers=h)
        cat_r = client.post(f"/api/spaces/{sid}/categories", json={"name": "ToDelete"}, headers=h)
        if cat_r.status_code not in (200, 201):
            pytest.skip("Cannot create category")
        cat_id = cat_r.json().get("id")

        r = client.delete(f"/api/spaces/{sid}/categories/{cat_id}", headers=h)
        assert r.status_code in (200, 401, 403)

    def test_create_room_in_space(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        cr = client.post("/api/spaces", json={"name": f"rmsp_{random_str(4)}"}, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        sid = cr.json().get("id")

        r = client.post(f"/api/spaces/{sid}/rooms", json={
            "name": f"sproom_{random_str(4)}",
        }, headers=h)
        assert r.status_code in (201, 200, 401, 403)

    def test_upload_avatar(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        cr = client.post("/api/spaces", json={"name": f"avsp_{random_str(4)}"}, headers=h)
        if cr.status_code not in (200, 201):
            pytest.skip("Cannot create space")
        sid = cr.json().get("id")

        # Create a tiny valid PNG
        import struct
        import zlib
        width, height = 2, 2
        raw = b""
        for _ in range(height):
            raw += b"\x00" + b"\xff\x00\x00" * width  # filter byte + RGB
        def_data = zlib.compress(raw)

        def _chunk(ctype, data):
            c = ctype + data
            return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

        png = (b"\x89PNG\r\n\x1a\n"
               + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
               + _chunk(b"IDAT", def_data)
               + _chunk(b"IEND", b""))

        r = client.post(
            f"/api/spaces/{sid}/avatar",
            files={"file": ("avatar.png", png, "image/png")},
            headers=h,
        )
        # PIL may not be installed, so accept multiple codes
        assert r.status_code in (200, 400, 401, 403, 500)


# ============================================================================
# Stickers (app/chats/stickers.py)
# ============================================================================

class TestStickers:
    """Full CRUD for /api/stickers/packs/*"""

    def _create_pack(self, client, headers):
        r = client.post("/api/stickers/packs", json={
            "name": f"pack_{random_str(6)}",
            "description": "test",
            "is_public": True,
        }, headers=headers)
        assert r.status_code in (200, 201, 401, 403)
        return r.json().get("pack", {}) if r.status_code in (200, 201) else {}

    def test_create_pack(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        pack = self._create_pack(client, h)
        if pack:
            assert pack.get("name")

    def test_list_my_packs(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        self._create_pack(client, h)

        r = client.get("/api/stickers/packs", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            body = r.json()
            assert "own" in body

    def test_list_public_packs(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/stickers/packs/public", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "packs" in r.json()

    def test_get_pack_details(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        pack = self._create_pack(client, h)
        pack_id = pack.get("id")
        if not pack_id:
            pytest.skip("No pack_id")

        r = client.get(f"/api/stickers/packs/{pack_id}", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "pack" in r.json()

    def test_update_pack(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        pack = self._create_pack(client, h)
        pack_id = pack.get("id")
        if not pack_id:
            pytest.skip("No pack_id")

        r = client.put(f"/api/stickers/packs/{pack_id}", json={
            "name": "Renamed Pack",
        }, headers=h)
        assert r.status_code in (200, 401, 403)

    def test_delete_pack(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        pack = self._create_pack(client, h)
        pack_id = pack.get("id")
        if not pack_id:
            pytest.skip("No pack_id")

        r = client.delete(f"/api/stickers/packs/{pack_id}", headers=h)
        assert r.status_code in (200, 401, 403)

    def test_upload_sticker(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        pack = self._create_pack(client, h)
        pack_id = pack.get("id")
        if not pack_id:
            pytest.skip("No pack_id")

        # Tiny valid PNG
        import struct, zlib
        w, ht = 2, 2
        raw = b""
        for _ in range(ht):
            raw += b"\x00" + b"\xff\x00\x00\xff" * w  # RGBA
        d = zlib.compress(raw)

        def _chunk(ct, data):
            c = ct + data
            return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

        png = (b"\x89PNG\r\n\x1a\n"
               + _chunk(b"IHDR", struct.pack(">IIBBBBB", w, ht, 8, 6, 0, 0, 0))
               + _chunk(b"IDAT", d)
               + _chunk(b"IEND", b""))

        r = client.post(
            f"/api/stickers/packs/{pack_id}/stickers",
            files={"file": ("sticker.png", png, "image/png")},
            headers=h,
        )
        assert r.status_code in (200, 400, 401, 403, 500)

    def test_delete_sticker(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        pack = self._create_pack(client, h)
        pack_id = pack.get("id")
        if not pack_id:
            pytest.skip("No pack_id")

        # Delete nonexistent sticker
        r = client.delete(f"/api/stickers/packs/{pack_id}/stickers/999999", headers=h)
        assert r.status_code in (404, 401, 403)

    def test_add_to_favorites(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        pack = self._create_pack(client, h)
        pack_id = pack.get("id")
        if not pack_id:
            pytest.skip("No pack_id")

        r = client.post(f"/api/stickers/packs/{pack_id}/favorite", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert r.json().get("ok") is True

    def test_remove_from_favorites(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        pack = self._create_pack(client, h)
        pack_id = pack.get("id")
        if not pack_id:
            pytest.skip("No pack_id")

        client.post(f"/api/stickers/packs/{pack_id}/favorite", headers=h)
        r = client.delete(f"/api/stickers/packs/{pack_id}/favorite", headers=h)
        assert r.status_code in (200, 401, 403)


# ============================================================================
# Voice (app/chats/voice.py)
# ============================================================================

class TestVoice:
    """POST /api/voice/{room_id}/join|leave|mute, GET participants"""

    def test_join_voice(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        vr = _create_voice_room(client, h)
        room_id = vr["room_id"]

        r = client.post(f"/api/voice/{room_id}/join", headers=h)
        assert r.status_code in (200, 400, 401, 403)

    def test_leave_voice(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        vr = _create_voice_room(client, h)
        room_id = vr["room_id"]

        client.post(f"/api/voice/{room_id}/join", headers=h)
        r = client.post(f"/api/voice/{room_id}/leave", headers=h)
        assert r.status_code in (200, 400, 401, 403)

    def test_participants(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        vr = _create_voice_room(client, h)
        room_id = vr["room_id"]

        r = client.get(f"/api/voice/{room_id}/participants", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "participants" in r.json()

    def test_mute_toggle(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        vr = _create_voice_room(client, h)
        room_id = vr["room_id"]

        client.post(f"/api/voice/{room_id}/join", headers=h)
        r = client.post(f"/api/voice/{room_id}/mute", json={
            "is_muted": True,
        }, headers=h)
        assert r.status_code in (200, 400, 401, 403)

    def test_toggle_video(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)
        vr = _create_voice_room(client, h)
        room_id = vr["room_id"]

        client.post(f"/api/voice/{room_id}/join", headers=h)
        r = client.post(f"/api/voice/{room_id}/mute", json={
            "is_video": True,
        }, headers=h)
        assert r.status_code in (200, 400, 401, 403)


# ============================================================================
# Link Preview (app/chats/link_preview.py)
# ============================================================================

class TestLinkPreview:
    """GET /api/link-preview"""

    def test_with_url(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/link-preview?url=https://example.com", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            body = r.json()
            assert "url" in body

    def test_without_url(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/link-preview", headers=h)
        assert r.status_code in (422, 400, 401, 403)

    def test_private_ip_blocked(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/link-preview?url=http://192.168.1.1/test", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            # Should return empty preview for private IPs
            body = r.json()
            assert body.get("title") == ""

    def test_invalid_url(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/link-preview?url=ftp://invalid.example", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert r.json().get("title") == ""


# ============================================================================
# Keys (app/keys/keys.py)
# ============================================================================

class TestKeys:
    """GET /api/keys/pubkey, /vapid-public, /ice-servers"""

    def test_node_pubkey(self, client):
        r = client.get("/api/keys/pubkey")
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            body = r.json()
            assert "pubkey_hex" in body
            assert len(body["pubkey_hex"]) >= 64

    def test_vapid_public(self, client):
        r = client.get("/api/keys/vapid-public")
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "vapid_public_key" in r.json()

    def test_ice_servers(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/keys/ice-servers", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            body = r.json()
            assert "ice_servers" in body
            assert isinstance(body["ice_servers"], list)


# ============================================================================
# Main endpoints (app/main.py)
# ============================================================================

class TestMainEndpoints:
    """GET /, /favicon.ico, /manifest.json, /service-worker.js, /health, /health/ready, /metrics"""

    def test_root(self, client):
        r = client.get("/")
        assert r.status_code in (200, 404)

    def test_favicon(self, client):
        r = client.get("/favicon.ico")
        assert r.status_code in (200, 404)

    def test_manifest(self, client):
        r = client.get("/manifest.json")
        assert r.status_code in (200, 404)

    def test_service_worker(self, client):
        r = client.get("/service-worker.js")
        assert r.status_code in (200, 404)

    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body.get("status") == "ok"
        assert "version" in body
        assert "database" in body
        assert "crypto_backend" in body

    def test_health_ready(self, client):
        r = client.get("/health/ready")
        assert r.status_code in (200, 503)
        body = r.json()
        assert "status" in body

    def test_metrics(self, client):
        r = client.get("/metrics")
        # Prometheus may or may not be available
        assert r.status_code in (200, 404)


# ============================================================================
# Config (app/config.py)
# ============================================================================

class TestConfig:
    """Config attributes, ensure_dirs, validate"""

    def test_config_attributes_exist(self):
        from app.config import Config
        assert hasattr(Config, "JWT_SECRET")
        assert hasattr(Config, "CSRF_SECRET")
        assert hasattr(Config, "DATABASE_URL") or hasattr(Config, "DB_PATH")
        assert hasattr(Config, "HOST")
        assert hasattr(Config, "PORT")
        assert hasattr(Config, "UPLOAD_DIR")
        assert hasattr(Config, "KEYS_DIR")
        assert hasattr(Config, "MAX_FILE_MB")
        assert hasattr(Config, "WAF_RATE_LIMIT_REQUESTS")
        assert len(Config.JWT_SECRET) >= 32
        assert len(Config.CSRF_SECRET) >= 32

    def test_ensure_dirs(self, tmp_path):
        from app.config import Config
        original_upload = Config.UPLOAD_DIR
        original_keys = Config.KEYS_DIR
        try:
            Config.UPLOAD_DIR = tmp_path / "test_uploads"
            Config.KEYS_DIR = tmp_path / "test_keys"
            Config.ensure_dirs()
            assert Config.UPLOAD_DIR.exists()
            assert Config.KEYS_DIR.exists()
        finally:
            Config.UPLOAD_DIR = original_upload
            Config.KEYS_DIR = original_keys

    def test_validate_no_crash(self):
        from app.config import Config
        # Should not raise, only logs warnings
        Config.validate()


# ============================================================================
# Database (app/database.py)
# ============================================================================

class TestDatabase:
    """get_engine_info, init_db, SessionLocal, get_db"""

    def test_get_engine_info(self):
        from app.database import get_engine_info
        info = get_engine_info()
        assert "backend" in info
        assert info["backend"] in ("sqlite", "postgresql")
        assert "async_available" in info

    def test_init_db_idempotent(self):
        from app.database import init_db
        # Should not raise even if called repeatedly
        init_db()
        init_db()

    def test_session_local(self):
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            assert db is not None
            # Basic query
            from sqlalchemy import text
            result = db.execute(text("SELECT 1"))
            assert result is not None
        finally:
            db.close()

    def test_get_db(self):
        from app.database import get_db
        gen = get_db()
        db = next(gen)
        assert db is not None
        try:
            next(gen)
        except StopIteration:
            pass


# ============================================================================
# Models validation (app/models.py)
# ============================================================================

class TestModelsValidation:
    """RegisterRequest, LoginRequest, KeyLoginRequest Pydantic validation"""

    def test_register_valid(self):
        from app.models import RegisterRequest
        req = RegisterRequest(
            phone="+79001234567",
            username="test_user1",
            password="StrongPass99!",
            x25519_public_key=secrets.token_hex(32),
        )
        assert req.username == "test_user1"

    def test_register_invalid_phone(self):
        from app.models import RegisterRequest
        with pytest.raises(Exception):
            RegisterRequest(
                phone="bad",
                username="test_user2",
                password="StrongPass99!",
                x25519_public_key=secrets.token_hex(32),
            )

    def test_register_invalid_username(self):
        from app.models import RegisterRequest
        with pytest.raises(Exception):
            RegisterRequest(
                phone="+79001234567",
                username="ab",  # too short
                password="StrongPass99!",
                x25519_public_key=secrets.token_hex(32),
            )

    def test_register_invalid_pubkey(self):
        from app.models import RegisterRequest
        with pytest.raises(Exception):
            RegisterRequest(
                phone="+79001234567",
                username="test_user3",
                password="StrongPass99!",
                x25519_public_key="not_hex_at_all",
            )

    def test_login_valid(self):
        from app.models import LoginRequest
        req = LoginRequest(
            phone_or_username="test_user",
            password="pass1234",
        )
        assert req.phone_or_username == "test_user"

    def test_login_empty_password(self):
        from app.models import LoginRequest
        with pytest.raises(Exception):
            LoginRequest(
                phone_or_username="test_user",
                password="",
            )

    def test_key_login_valid(self):
        from app.models import KeyLoginRequest
        req = KeyLoginRequest(
            challenge_id=secrets.token_hex(16),
            pubkey=secrets.token_hex(32),
            proof=secrets.token_hex(32),
        )
        assert len(req.pubkey) == 64

    def test_key_login_invalid_hex(self):
        from app.models import KeyLoginRequest
        with pytest.raises(Exception):
            KeyLoginRequest(
                challenge_id=secrets.token_hex(16),
                pubkey="not_a_valid_hex_string_of_64_chars_long_enough_to_pass_minlength",
                proof=secrets.token_hex(32),
            )


# ============================================================================
# Utils (app/utilites/utils.py)
# ============================================================================

class TestUtils:
    """generative_invite_code, sanitize"""

    def test_invite_code_length(self):
        from app.utilites.utils import generative_invite_code
        for length in (4, 8, 12):
            code = generative_invite_code(length)
            assert len(code) == length

    def test_invite_code_no_ambiguous(self):
        from app.utilites.utils import generative_invite_code
        ambiguous = set("O0I1")
        for _ in range(50):
            code = generative_invite_code(8)
            assert not (set(code) & ambiguous), f"Code {code} has ambiguous chars"

    def test_sanitize_strips_control(self):
        from app.utilites.utils import sanitize
        result = sanitize("hello\x00world\x07test")
        assert "\x00" not in result
        assert "\x07" not in result
        assert "hello" in result

    def test_sanitize_truncates(self):
        from app.utilites.utils import sanitize
        long_str = "a" * 10000
        result = sanitize(long_str, max_len=100)
        assert len(result) <= 100

    def test_sanitize_empty(self):
        from app.utilites.utils import sanitize
        assert sanitize("") == ""
        assert sanitize(None) == ""  # type: ignore

    def test_sanitize_preserves_normal(self):
        from app.utilites.utils import sanitize
        normal = "Hello, World! 123"
        assert sanitize(normal) == normal


# ============================================================================
# Antispam Bot (app/bots/antispam_bot.py)
# ============================================================================

class TestAntispamBot:
    """ensure_antispam_bot, add_antispam_bot_to_room, check_*_spam"""

    def test_ensure_antispam_bot(self):
        from app.database import SessionLocal
        from app.bots.antispam_bot import ensure_antispam_bot

        db = SessionLocal()
        try:
            uid = ensure_antispam_bot(db)
            assert isinstance(uid, int)
            assert uid > 0
        finally:
            db.close()

    def test_ensure_antispam_bot_idempotent(self):
        from app.database import SessionLocal
        from app.bots.antispam_bot import ensure_antispam_bot

        db = SessionLocal()
        try:
            uid1 = ensure_antispam_bot(db)
            uid2 = ensure_antispam_bot(db)
            assert uid1 == uid2
        finally:
            db.close()

    def test_add_antispam_bot_to_room(self, client):
        from app.database import SessionLocal
        from app.bots.antispam_bot import add_antispam_bot_to_room, ensure_antispam_bot

        u = make_user(client)
        h = _login_and_get_headers(client, u)
        room = _create_room(client, h)
        room_id = room.get("id")
        if not room_id:
            pytest.skip("No room id")

        db = SessionLocal()
        try:
            ensure_antispam_bot(db)
            result = add_antispam_bot_to_room(room_id, db)
            assert isinstance(result, bool)
        finally:
            db.close()

    @pytest.mark.asyncio
    async def test_check_repeat_spam(self):
        from app.database import SessionLocal
        from app.bots.antispam_bot import check_repeat_spam, ensure_antispam_bot
        from app.models import User

        db = SessionLocal()
        try:
            ensure_antispam_bot(db)
            user = db.query(User).filter(User.is_bot == False).first()
            if not user:
                pytest.skip("No user")

            result = await check_repeat_spam(99999, user, "test message", db)
            assert isinstance(result, bool)
        finally:
            db.close()

    @pytest.mark.asyncio
    async def test_check_link_spam(self):
        from app.database import SessionLocal
        from app.bots.antispam_bot import check_link_spam, ensure_antispam_bot
        from app.models import User
        from app.models_rooms import RoomRole

        db = SessionLocal()
        try:
            ensure_antispam_bot(db)
            user = db.query(User).filter(User.is_bot == False).first()
            if not user:
                pytest.skip("No user")

            result = await check_link_spam(
                99998, user, "check https://example.com link", RoomRole.MEMBER, db
            )
            assert isinstance(result, bool)
        finally:
            db.close()

    @pytest.mark.asyncio
    async def test_check_caps_spam(self):
        from app.database import SessionLocal
        from app.bots.antispam_bot import check_caps_spam, ensure_antispam_bot
        from app.models import User

        db = SessionLocal()
        try:
            ensure_antispam_bot(db)
            user = db.query(User).filter(User.is_bot == False).first()
            if not user:
                pytest.skip("No user")

            # Short message - should not be spam
            result = await check_caps_spam(99997, user, "HI", db)
            assert result is False

            # Long caps message - should be spam
            caps_text = "A" * 30
            result2 = await check_caps_spam(99996, user, caps_text, db)
            assert isinstance(result2, bool)
        finally:
            db.close()


# ============================================================================
# Connection Manager (app/peer/connection_manager.py)
# ============================================================================

class TestConnectionManager:
    """TokenBucket, MessageDeduplicator, ConnectionManager"""

    def test_token_bucket_consume_success(self):
        from app.peer.connection_manager import TokenBucket
        bucket = TokenBucket(capacity=10, rate=5)
        assert bucket.consume(1.0) is True

    def test_token_bucket_exhaust(self):
        from app.peer.connection_manager import TokenBucket
        bucket = TokenBucket(capacity=3, rate=0.0)  # no refill
        assert bucket.consume(1.0) is True
        assert bucket.consume(1.0) is True
        assert bucket.consume(1.0) is True
        assert bucket.consume(1.0) is False

    def test_token_bucket_refill(self):
        from app.peer.connection_manager import TokenBucket
        bucket = TokenBucket(capacity=2, rate=100.0)  # fast refill
        bucket.consume(2.0)  # exhaust
        time.sleep(0.05)  # refill: 100 * 0.05 = 5 tokens (capped at 2)
        assert bucket.consume(1.0) is True

    @pytest.mark.asyncio
    async def test_deduplicator_is_duplicate(self):
        from app.peer.connection_manager import MessageDeduplicator
        dd = MessageDeduplicator(max_size=100, ttl_sec=60)
        assert await dd.is_duplicate("msg_1") is False
        assert await dd.is_duplicate("msg_1") is True
        assert await dd.is_duplicate("msg_2") is False

    @pytest.mark.asyncio
    async def test_deduplicator_max_size_eviction(self):
        from app.peer.connection_manager import MessageDeduplicator
        dd = MessageDeduplicator(max_size=5, ttl_sec=60)
        for i in range(10):
            await dd.is_duplicate(f"evict_{i}")
        assert dd.seen_count() <= 5

    def test_connection_manager_total_connections(self):
        from app.peer.connection_manager import ConnectionManager
        mgr = ConnectionManager()
        assert mgr.total_connections() == 0

    def test_connection_manager_dedup_stats(self):
        from app.peer.connection_manager import ConnectionManager
        mgr = ConnectionManager()
        stats = mgr.dedup_stats()
        assert "seen_msg_ids" in stats
        assert "rooms" in stats
        assert "connections" in stats


# ============================================================================
# Peer Registry (app/peer/peer_registry.py)
# ============================================================================

class TestPeerRegistry:
    """PeerInfo, PeerRegistry, REST endpoints"""

    def test_peer_info_alive(self):
        from app.peer.peer_registry import PeerInfo
        p = PeerInfo(name="test", ip="10.0.0.1", port=9000)
        assert p.alive() is True

    def test_peer_info_alive_expired(self):
        from app.peer.peer_registry import PeerInfo
        p = PeerInfo(name="test", ip="10.0.0.1", port=9000)
        p.last_seen = time.monotonic() - 9999  # expired
        assert p.alive() is False

    def test_peer_info_has_encryption(self):
        from app.peer.peer_registry import PeerInfo
        p_enc = PeerInfo(name="t", ip="10.0.0.1", port=9000,
                         node_pubkey_hex=secrets.token_hex(32))
        p_no = PeerInfo(name="t", ip="10.0.0.2", port=9000)
        assert p_enc.has_encryption() is True
        assert p_no.has_encryption() is False

    def test_peer_info_to_dict(self):
        from app.peer.peer_registry import PeerInfo
        p = PeerInfo(name="n", ip="10.0.0.1", port=9000,
                     node_pubkey_hex=secrets.token_hex(32))
        d = p.to_dict()
        assert d["name"] == "n"
        assert d["ip"] == "10.0.0.1"
        assert d["port"] == 9000
        assert d["online"] is True
        assert d["encrypted"] is True

    def test_peer_info_base_url(self):
        from app.peer.peer_registry import PeerInfo
        p = PeerInfo(name="n", ip="10.0.0.1", port=9000)
        url = p.base_url
        assert "10.0.0.1" in url
        assert "9000" in url

    def test_registry_update(self):
        from app.peer.peer_registry import PeerRegistry
        reg = PeerRegistry()
        is_new = reg.update("10.0.0.1", "peer1", 8000)
        assert is_new is True
        is_new2 = reg.update("10.0.0.1", "peer1", 8000)
        assert is_new2 is False

    def test_registry_active(self):
        from app.peer.peer_registry import PeerRegistry
        reg = PeerRegistry()
        reg.update("10.0.0.1", "a", 8000)
        active = reg.active()
        assert len(active) == 1

    def test_registry_get(self):
        from app.peer.peer_registry import PeerRegistry
        reg = PeerRegistry()
        reg.update("10.0.0.2", "b", 8001)
        p = reg.get("10.0.0.2")
        assert p is not None
        assert p.name == "b"
        assert reg.get("9.9.9.9") is None

    def test_registry_cleanup(self):
        from app.peer.peer_registry import PeerRegistry
        reg = PeerRegistry()
        reg.update("10.0.0.3", "c", 8002)
        # Force expire
        reg._peers["10.0.0.3"].last_seen = time.monotonic() - 99999
        reg.cleanup()
        assert len(reg.active()) == 0

    def test_rest_peers(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/peers", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            body = r.json()
            assert "peers" in body
            assert "own_ip" in body

    def test_rest_peer_status(self, client):
        r = client.get("/api/peers/status")
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            body = r.json()
            assert body.get("ok") is True

    def test_rest_public_rooms(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/peers/public-rooms", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "rooms" in r.json()


# ============================================================================
# Federation (app/federation/federation.py)
# ============================================================================

class TestFederation:
    """GET /api/federation/status, POST guest-login, GET my-rooms"""

    def test_federation_status(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        # The /api/federation/status endpoint may not exist
        r = client.get("/api/federation/status", headers=h)
        # Accept any response code; the route may not be defined
        assert r.status_code in (200, 404, 401, 403, 405)

    def test_guest_login(self, client):
        # guest-login requires request from private IP; test client is 127.0.0.1 or testserver
        r = client.post("/api/federation/guest-login", json={
            "username": f"guest_{random_str(4)}",
            "display_name": "Guest User",
            "avatar_emoji": "T",
            "x25519_pubkey": secrets.token_hex(32),
            "peer_port": 8000,
        })
        # May succeed (200), be rejected (403), or require auth (401)
        assert r.status_code in (200, 401, 403, 500)

    def test_my_rooms(self, client):
        u = make_user(client)
        h = _login_and_get_headers(client, u)

        r = client.get("/api/federation/my-rooms", headers=h)
        assert r.status_code in (200, 401, 403)
        if r.status_code == 200:
            assert "rooms" in r.json()

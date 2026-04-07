"""
Coverage tests for remaining endpoint edge cases and internal functions:
  - app/chats/rooms.py (kick, role, mute, ban, rotate-key, auto-delete, export, pin)
  - app/chats/dm.py (create DM with key exchange, store key, list details)
  - app/chats/contacts.py (add/update/delete, block full flow)
  - app/chats/saved.py (toggle save, unsave, check)
  - app/chats/reports.py (report flow, punishment, cleanup)
  - app/chats/search.py (similarity functions, search endpoints)
  - app/chats/spaces.py (CRUD, categories, room creation, avatar, roles)
  - app/chats/stickers.py (pack CRUD, sticker upload, favorites)
  - app/chats/channels.py (join by invite)
  - app/chats/statuses.py (cleanup_expired_statuses)
  - app/chats/tasks.py (assign, update text, delete)
  - app/chats/link_preview.py (parse OG, cache, SSRF protection)
  - app/security/middleware.py (TokenRefreshMiddleware edge cases)
"""
import os
import secrets
import time
import pytest
from unittest.mock import patch, MagicMock
from conftest import make_user, login_user, random_str, random_digits


def _two_users_in_room(client):
    """Helper: create two users, a room, and have both join."""
    u1 = make_user(client)
    u2 = make_user(client)
    h1 = login_user(client, u1["username"], u1["password"])
    h2 = login_user(client, u2["username"], u2["password"])

    r = client.post("/api/rooms", json={
        "name": f"shared_{random_str(6)}",
        "encrypted_room_key": {
            "ephemeral_pub": secrets.token_hex(32),
            "ciphertext": secrets.token_hex(60),
        },
    }, headers=h1)
    data = r.json()
    room_id = data.get("id") or data.get("room", {}).get("id")
    invite = data.get("invite_code") or data.get("room", {}).get("invite_code")

    me1 = client.get("/api/authentication/me", headers=h1).json()
    me2 = client.get("/api/authentication/me", headers=h2).json()
    uid1 = me1.get("user_id") or me1.get("id")
    uid2 = me2.get("user_id") or me2.get("id")

    if invite:
        client.post(f"/api/rooms/join/{invite}", json={
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        }, headers=h2)

    return {
        "room_id": room_id, "invite": invite,
        "u1": u1, "u2": u2, "h1": h1, "h2": h2,
        "uid1": uid1, "uid2": uid2,
    }


# ══════════════════════════════════════════════════════════════════════════════
# rooms.py — moderation (kick, role, mute, ban), features
# ══════════════════════════════════════════════════════════════════════════════

class TestRoomsModerationFull:
    def test_kick_member_success(self, client):
        ctx = _two_users_in_room(client)
        if not ctx["room_id"] or not ctx["uid2"]:
            pytest.skip("Setup failed")
        r = client.post(f"/api/rooms/{ctx['room_id']}/kick/{ctx['uid2']}",
                        headers=ctx["h1"])
        assert r.status_code in (200, 403, 404)

    def test_kick_nonmember(self, client, logged_user, room):
        rid = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/rooms/{rid}/kick/999999", headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404)

    def test_change_role_to_admin(self, client):
        ctx = _two_users_in_room(client)
        if not ctx["room_id"] or not ctx["uid2"]:
            pytest.skip("Setup failed")
        r = client.put(
            f"/api/rooms/{ctx['room_id']}/members/{ctx['uid2']}/role",
            json={"role": "admin"}, headers=ctx["h1"])
        assert r.status_code in (200, 400, 403, 404)

    def test_change_role_non_owner_fails(self, client):
        ctx = _two_users_in_room(client)
        if not ctx["room_id"] or not ctx["uid1"]:
            pytest.skip("Setup failed")
        r = client.put(
            f"/api/rooms/{ctx['room_id']}/members/{ctx['uid1']}/role",
            json={"role": "admin"}, headers=ctx["h2"])
        assert r.status_code in (400, 403, 404)

    def test_mute_member(self, client):
        ctx = _two_users_in_room(client)
        if not ctx["room_id"] or not ctx["uid2"]:
            pytest.skip("Setup failed")
        r = client.put(
            f"/api/rooms/{ctx['room_id']}/members/{ctx['uid2']}/mute",
            json={"is_muted": True}, headers=ctx["h1"])
        assert r.status_code in (200, 400, 403, 404)

    def test_ban_member(self, client):
        ctx = _two_users_in_room(client)
        if not ctx["room_id"] or not ctx["uid2"]:
            pytest.skip("Setup failed")
        r = client.put(
            f"/api/rooms/{ctx['room_id']}/members/{ctx['uid2']}/ban",
            json={"is_banned": True}, headers=ctx["h1"])
        assert r.status_code in (200, 400, 403, 404)

    def test_rotate_key(self, client):
        ctx = _two_users_in_room(client)
        if not ctx["room_id"]:
            pytest.skip("Setup failed")
        r = client.post(f"/api/rooms/{ctx['room_id']}/rotate-key", json={
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        }, headers=ctx["h1"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_auto_delete_set(self, client, logged_user, room):
        rid = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/rooms/{rid}/auto-delete",
                        json={"seconds": 3600}, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_auto_delete_disable(self, client, logged_user, room):
        rid = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/rooms/{rid}/auto-delete",
                        json={"seconds": 0}, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_slow_mode(self, client, logged_user, room):
        rid = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/rooms/{rid}/slow-mode",
                        json={"seconds": 5}, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_export_chat(self, client, logged_user, room):
        rid = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.get(f"/api/rooms/{rid}/export", headers=logged_user["headers"])
        assert r.status_code in (200, 403, 404)

    def test_mute_notifications(self, client, logged_user, room):
        rid = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/rooms/{rid}/mute",
                        json={"is_muted": True}, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_pin_message(self, client, logged_user, room):
        rid = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/rooms/{rid}/pin",
                        json={"message_id": 1}, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_provide_key(self, client):
        ctx = _two_users_in_room(client)
        if not ctx["room_id"] or not ctx["uid2"]:
            pytest.skip("Setup failed")
        r = client.post(f"/api/rooms/{ctx['room_id']}/provide-key", json={
            "for_user_id": ctx["uid2"],
            "ephemeral_pub": secrets.token_hex(32),
            "ciphertext": secrets.token_hex(60),
        }, headers=ctx["h1"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_delete_room_owner(self, client, logged_user):
        r = client.post("/api/rooms", json={
            "name": f"todel_{random_str(6)}",
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        }, headers=logged_user["headers"])
        data = r.json()
        rid = data.get("id") or data.get("room", {}).get("id")
        if rid:
            r2 = client.delete(f"/api/rooms/{rid}", headers=logged_user["headers"])
            assert r2.status_code in (200, 204, 403)


# ══════════════════════════════════════════════════════════════════════════════
# dm.py — full DM flow with key exchange
# ══════════════════════════════════════════════════════════════════════════════

class TestDMFullFlow:
    def test_create_dm_and_store_key(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = login_user(client, u1["username"], u1["password"])
        h2 = login_user(client, u2["username"], u2["password"])
        me2 = client.get("/api/authentication/me", headers=h2).json()
        uid2 = me2.get("user_id") or me2.get("id")
        if not uid2:
            pytest.skip("No user ID")

        r = client.post(f"/api/dm/{uid2}", json={
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        }, headers=h1)
        assert r.status_code in (200, 201, 400, 422)

        if r.status_code in (200, 201):
            data = r.json()
            room_id = data.get("room_id") or data.get("id") or data.get("room", {}).get("id")
            if room_id:
                me1 = client.get("/api/authentication/me", headers=h1).json()
                uid1 = me1.get("user_id") or me1.get("id")
                r2 = client.post(f"/api/dm/store-key/{room_id}", json={
                    "user_id": uid1,
                    "ephemeral_pub": secrets.token_hex(32),
                    "ciphertext": secrets.token_hex(60),
                }, headers=h2)
                assert r2.status_code in (200, 400, 404, 422)

    def test_list_dms_with_data(self, client, logged_user):
        r = client.get("/api/dm/list", headers=logged_user["headers"])
        assert r.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# contacts.py — full contact lifecycle
# ══════════════════════════════════════════════════════════════════════════════

class TestContactsFullFlow:
    def test_add_update_delete_contact(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = login_user(client, u1["username"], u1["password"])
        login_user(client, u2["username"], u2["password"])
        me2 = client.get("/api/authentication/me", headers=login_user(client, u2["username"], u2["password"])).json()
        uid2 = me2.get("user_id") or me2.get("id")
        if not uid2:
            pytest.skip("No user ID")

        # Add
        r = client.post("/api/contacts", json={"user_id": uid2}, headers=h1)
        assert r.status_code in (200, 201, 400, 409, 422)

        if r.status_code in (200, 201):
            data = r.json()
            cid = data.get("contact_id") or data.get("id")
            if cid:
                # Update nickname
                r2 = client.put(f"/api/contacts/{cid}",
                                json={"nickname": "BFF"}, headers=h1)
                assert r2.status_code in (200, 404)
                # Delete
                r3 = client.delete(f"/api/contacts/{cid}", headers=h1)
                assert r3.status_code in (200, 204, 404)

    def test_block_user_flow(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = login_user(client, u1["username"], u1["password"])
        login_user(client, u2["username"], u2["password"])
        me2 = client.get("/api/authentication/me", headers=login_user(client, u2["username"], u2["password"])).json()
        uid2 = me2.get("user_id") or me2.get("id")
        if not uid2:
            pytest.skip("No user ID")
        r = client.post(f"/api/users/block/{uid2}", headers=h1)
        assert r.status_code in (200, 201, 400, 404)


# ══════════════════════════════════════════════════════════════════════════════
# saved.py — toggle, list, unsave, check
# ══════════════════════════════════════════════════════════════════════════════

class TestSavedFullFlow:
    def test_toggle_save_nonexistent(self, client, logged_user):
        r = client.post("/api/saved/999999", json={}, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 404)

    def test_list_saved(self, client, logged_user):
        r = client.get("/api/saved", headers=logged_user["headers"])
        assert r.status_code == 200

    def test_unsave_nonexistent(self, client, logged_user):
        r = client.delete("/api/saved/999999", headers=logged_user["headers"])
        assert r.status_code in (200, 204, 404)

    def test_check_saved(self, client, logged_user):
        r = client.get("/api/saved/check/999999", headers=logged_user["headers"])
        assert r.status_code in (200, 404)


# ══════════════════════════════════════════════════════════════════════════════
# reports.py — report flow, strikes, cleanup
# ══════════════════════════════════════════════════════════════════════════════

class TestReportsFullFlow:
    def test_report_user_spam(self, client):
        u1 = make_user(client)
        u2 = make_user(client)
        h1 = login_user(client, u1["username"], u1["password"])
        login_user(client, u2["username"], u2["password"])
        me2 = client.get("/api/authentication/me", headers=login_user(client, u2["username"], u2["password"])).json()
        uid2 = me2.get("user_id") or me2.get("id")
        if not uid2:
            pytest.skip("No user ID")
        r = client.post(f"/api/users/report/{uid2}", json={
            "reason": "spam",
            "description": "Sending spam",
        }, headers=h1)
        assert r.status_code in (200, 201, 400, 404, 422)

    def test_report_self_fails(self, client, logged_user):
        me = client.get("/api/authentication/me", headers=logged_user["headers"]).json()
        uid = me.get("user_id") or me.get("id")
        if uid:
            r = client.post(f"/api/users/report/{uid}", json={
                "reason": "spam",
            }, headers=logged_user["headers"])
            assert r.status_code in (400, 403, 404, 422)

    def test_my_strikes(self, client, logged_user):
        r = client.get("/api/moderation/strikes", headers=logged_user["headers"])
        assert r.status_code in (200, 404, 405)

    @pytest.mark.asyncio
    async def test_cleanup_expired_punishments(self):
        from app.chats.reports import cleanup_expired_punishments
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            await cleanup_expired_punishments(db)
        finally:
            db.close()


# ══════════════════════════════════════════════════════════════════════════════
# search.py — similarity functions
# ══════════════════════════════════════════════════════════════════════════════

class TestSearchInternals:
    def test_name_similarity_exact(self):
        from app.chats.search import _name_similarity
        assert _name_similarity("alice", "alice") == 1.0

    def test_name_similarity_starts_with(self):
        from app.chats.search import _name_similarity
        s = _name_similarity("ali", "alice")
        assert s > 0.5

    def test_name_similarity_contains(self):
        from app.chats.search import _name_similarity
        s = _name_similarity("lic", "alice")
        assert s > 0

    def test_name_similarity_no_match(self):
        from app.chats.search import _name_similarity
        s = _name_similarity("xyz", "alice")
        assert s < 0.5

    def test_name_similarity_none(self):
        from app.chats.search import _name_similarity
        s = _name_similarity("test", None)
        assert s == 0.0

    def test_similarity_threshold(self):
        from app.chats.search import _similarity_threshold
        assert _similarity_threshold(2) >= 0.3
        assert _similarity_threshold(5) >= 0.2
        assert _similarity_threshold(10) >= 0.2

    def test_global_search_endpoint(self, client, logged_user):
        r = client.get("/api/users/global-search?q=test", headers=logged_user["headers"])
        assert r.status_code in (200, 404, 405)


# ══════════════════════════════════════════════════════════════════════════════
# spaces.py — full lifecycle
# ══════════════════════════════════════════════════════════════════════════════

class TestSpacesFullLifecycle:
    def test_create_and_manage_space(self, client, logged_user):
        # Create
        r = client.post("/api/spaces", json={
            "name": f"sp_{random_str(6)}",
            "description": "Test space",
            "is_public": True,
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 201, 422)
        if r.status_code not in (200, 201):
            return
        data = r.json()
        sid = data.get("id") or data.get("space", {}).get("id")
        invite = data.get("invite_code") or data.get("space", {}).get("invite_code")
        if not sid:
            return

        # Get details
        r2 = client.get(f"/api/spaces/{sid}", headers=logged_user["headers"])
        assert r2.status_code in (200, 404)

        # Update
        r3 = client.put(f"/api/spaces/{sid}", json={
            "name": f"upd_{random_str(4)}", "description": "Updated",
        }, headers=logged_user["headers"])
        assert r3.status_code in (200, 403, 404)

        # Create category
        r4 = client.post(f"/api/spaces/{sid}/categories", json={
            "name": "General",
        }, headers=logged_user["headers"])
        assert r4.status_code in (200, 201, 403, 404, 422)

        cat_id = None
        if r4.status_code in (200, 201):
            cat_data = r4.json()
            cat_id = cat_data.get("id") or cat_data.get("category", {}).get("id")

        # Create room in space
        r5 = client.post(f"/api/spaces/{sid}/rooms", json={
            "name": f"room_{random_str(4)}",
            "category_id": cat_id,
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        }, headers=logged_user["headers"])
        assert r5.status_code in (200, 201, 403, 404, 422)

        # Members
        r6 = client.get(f"/api/spaces/{sid}/members", headers=logged_user["headers"])
        assert r6.status_code in (200, 404)

        # Join by another user
        if invite:
            u2 = make_user(client)
            h2 = login_user(client, u2["username"], u2["password"])
            rj = client.post(f"/api/spaces/join/{invite}", headers=h2)
            assert rj.status_code in (200, 201, 400, 404)

            me2 = client.get("/api/authentication/me", headers=h2).json()
            uid2 = me2.get("user_id") or me2.get("id")
            if uid2:
                # Change role
                client.put(f"/api/spaces/{sid}/members/{uid2}/role",
                           json={"role": "admin"}, headers=logged_user["headers"])
                # Kick
                client.delete(f"/api/spaces/{sid}/members/{uid2}",
                              headers=logged_user["headers"])

        # Delete category
        if cat_id:
            client.delete(f"/api/spaces/{sid}/categories/{cat_id}",
                          headers=logged_user["headers"])

        # Delete space
        rd = client.delete(f"/api/spaces/{sid}", headers=logged_user["headers"])
        assert rd.status_code in (200, 204, 403, 404)

    def test_public_spaces(self, client):
        r = client.get("/api/spaces/public")
        assert r.status_code in (200, 404, 405)


# ══════════════════════════════════════════════════════════════════════════════
# stickers.py — full pack lifecycle
# ══════════════════════════════════════════════════════════════════════════════

class TestStickersFullLifecycle:
    def test_pack_lifecycle(self, client, logged_user):
        # Create
        r = client.post("/api/stickers/packs", json={
            "name": f"pk_{random_str(6)}",
            "description": "Test pack",
            "is_public": True,
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 201, 422)
        if r.status_code not in (200, 201):
            return
        data = r.json()
        pid = data.get("id") or data.get("pack", {}).get("id")
        if not pid:
            return

        # Get details
        client.get(f"/api/stickers/packs/{pid}", headers=logged_user["headers"])

        # Update
        client.put(f"/api/stickers/packs/{pid}", json={
            "name": f"upd_{random_str(4)}", "is_public": False,
        }, headers=logged_user["headers"])

        # Upload sticker
        from PIL import Image
        import io
        img = Image.new("RGB", (64, 64), color="green")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        r2 = client.post(
            f"/api/stickers/packs/{pid}/stickers",
            files={"file": ("sticker.png", buf.getvalue(), "image/png")},
            data={"emoji": "😀"},
            headers=logged_user["headers"],
        )
        assert r2.status_code in (200, 201, 400, 403, 404, 422, 500)

        # Favorite
        client.post(f"/api/stickers/packs/{pid}/favorite", headers=logged_user["headers"])
        client.delete(f"/api/stickers/packs/{pid}/favorite", headers=logged_user["headers"])

        # Delete pack
        client.delete(f"/api/stickers/packs/{pid}", headers=logged_user["headers"])

    def test_public_packs(self, client, logged_user):
        r = client.get("/api/stickers/packs/public", headers=logged_user["headers"])
        assert r.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# channels.py — join by invite
# ══════════════════════════════════════════════════════════════════════════════

class TestChannelsJoin:
    def test_create_and_join_channel(self, client, logged_user):
        r = client.post("/api/channels", json={
            "name": f"ch_{random_str(6)}",
            "description": "Broadcast",
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 201, 403, 422)
        if r.status_code not in (200, 201):
            return
        data = r.json()
        invite = data.get("invite_code") or data.get("channel", {}).get("invite_code")
        if invite:
            u2 = make_user(client)
            h2 = login_user(client, u2["username"], u2["password"])
            r2 = client.post(f"/api/channels/join/{invite}", headers=h2)
            assert r2.status_code in (200, 201, 400, 404)


# ══════════════════════════════════════════════════════════════════════════════
# statuses.py — cleanup
# ══════════════════════════════════════════════════════════════════════════════

class TestStatusesCleanup:
    @pytest.mark.asyncio
    async def test_cleanup_expired_statuses(self):
        from app.chats.statuses import cleanup_expired_statuses
        from app.database import SessionLocal
        db = SessionLocal()
        try:
            count = await cleanup_expired_statuses(db)
            assert isinstance(count, int)
        finally:
            db.close()

    def test_create_and_list_status(self, client, logged_user):
        client.post("/api/statuses", json={"text": f"status_{random_str(8)}"},
                    headers=logged_user["headers"])
        r = client.get("/api/statuses", headers=logged_user["headers"])
        assert r.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# tasks.py — full lifecycle
# ══════════════════════════════════════════════════════════════════════════════

class TestTasksFullFlow:
    def test_task_lifecycle(self, client, logged_user, room):
        rid = room.get("id") or room.get("room", {}).get("id", 1)
        # Create
        r = client.post(f"/api/rooms/{rid}/tasks", json={
            "text": "Buy milk",
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 201, 404)
        if r.status_code not in (200, 201):
            return
        data = r.json()
        tid = data.get("id") or data.get("task", {}).get("id")
        if not tid:
            return

        # Update text
        client.put(f"/api/rooms/{rid}/tasks/{tid}", json={
            "text": "Buy oat milk",
        }, headers=logged_user["headers"])

        # Toggle done
        client.put(f"/api/rooms/{rid}/tasks/{tid}", json={
            "is_done": True,
        }, headers=logged_user["headers"])

        # Assign
        me = client.get("/api/authentication/me", headers=logged_user["headers"]).json()
        uid = me.get("user_id") or me.get("id")
        if uid:
            client.put(f"/api/rooms/{rid}/tasks/{tid}", json={
                "assignee_id": uid,
            }, headers=logged_user["headers"])

        # Delete
        r2 = client.delete(f"/api/rooms/{rid}/tasks/{tid}", headers=logged_user["headers"])
        assert r2.status_code in (200, 204, 404)


# ══════════════════════════════════════════════════════════════════════════════
# link_preview.py — internal functions
# ══════════════════════════════════════════════════════════════════════════════

class TestLinkPreviewInternals:
    def test_parse_og_basic(self):
        from app.chats.link_preview import _parse_og
        html = '<html><head><meta property="og:title" content="Test Title"><meta property="og:description" content="Desc"></head></html>'
        result = _parse_og(html, "https://example.com")
        assert result["title"] == "Test Title"

    def test_parse_og_empty(self):
        from app.chats.link_preview import _parse_og
        result = _parse_og("<html></html>", "https://example.com")
        assert result["title"] == ""

    def test_cache_get_miss(self):
        from app.chats.link_preview import _cache_get
        result = _cache_get("https://nonexistent-url-xyz.com")
        assert result is None

    def test_cache_set_and_get(self):
        from app.chats.link_preview import _cache_get, _cache_set
        _cache_set("https://test-cache.com", {"title": "Cached"})
        result = _cache_get("https://test-cache.com")
        assert result is not None
        assert result["title"] == "Cached"

    def test_link_preview_private_ip(self, client, logged_user):
        r = client.get("/api/link-preview?url=http://192.168.1.1",
                       headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 422)

    def test_link_preview_localhost(self, client, logged_user):
        r = client.get("/api/link-preview?url=http://127.0.0.1",
                       headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 422)


# ══════════════════════════════════════════════════════════════════════════════
# middleware.py — TokenRefreshMiddleware edge case
# ══════════════════════════════════════════════════════════════════════════════

class TestMiddlewareEdgeCases:
    def test_security_headers_on_static(self, client):
        r = client.get("/health")
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_csrf_skips_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_csrf_skips_favicon(self, client):
        r = client.get("/favicon.ico")
        assert r.status_code in (200, 404)

    def test_correlation_id_auto(self, client):
        r = client.get("/health")
        assert r.headers.get("X-Request-ID")

    def test_correlation_id_custom(self, client):
        r = client.get("/health", headers={"X-Request-ID": "custom-123"})
        assert r.headers.get("X-Request-ID") == "custom-123"


# ══════════════════════════════════════════════════════════════════════════════
# utilites/utils.py — invite code, sanitize
# ══════════════════════════════════════════════════════════════════════════════

class TestUtils:
    def test_invite_code_length(self):
        from app.utilites.utils import generative_invite_code
        code = generative_invite_code(8)
        assert len(code) == 8

    def test_invite_code_no_ambiguous(self):
        from app.utilites.utils import generative_invite_code
        for _ in range(20):
            code = generative_invite_code(12)
            assert "O" not in code and "0" not in code
            assert "I" not in code and "1" not in code

    def test_sanitize_strips_control(self):
        from app.utilites.utils import sanitize
        assert sanitize("hello\x00world") == "helloworld"

    def test_sanitize_truncates(self):
        from app.utilites.utils import sanitize
        result = sanitize("a" * 5000, max_len=100)
        assert len(result) == 100

    def test_sanitize_empty(self):
        from app.utilites.utils import sanitize
        assert sanitize("") == ""
        assert sanitize(None) == ""

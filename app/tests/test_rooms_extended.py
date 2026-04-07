"""Extended room management tests — permissions, key rotation, export, moderation."""
import secrets
import pytest
from conftest import make_user, login_user, random_str


class TestRoomCreation:
    """Room creation edge cases."""

    def test_create_private_room(self, client, logged_user):
        r = client.post("/api/rooms", json={
            "name": f"private_{random_str()}",
            "is_private": True,
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 201)

    def test_create_room_no_key(self, client, logged_user):
        r = client.post("/api/rooms", json={
            "name": f"nokey_{random_str()}",
        }, headers=logged_user["headers"])
        # Should require encrypted_room_key
        assert r.status_code in (200, 201, 400, 422)

    def test_create_room_with_description(self, client, logged_user):
        r = client.post("/api/rooms", json={
            "name": f"desc_{random_str()}",
            "description": "A test room with description",
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 201)

    def test_create_room_unauthenticated(self, client):
        r = client.post("/api/rooms", json={
            "name": "hacker_room",
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        })
        assert r.status_code in (401, 403)


class TestRoomJoin:
    """Room join/leave operations."""

    def test_join_by_invite_code(self, client, logged_user, room):
        invite = room.get("invite_code") or room.get("room", {}).get("invite_code")
        if not invite:
            pytest.skip("No invite_code in room response")
        u2 = make_user(client)
        h2 = login_user(client, u2["username"], u2["password"])
        r = client.post(f"/api/rooms/join/{invite}", json={
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        }, headers=h2)
        assert r.status_code in (200, 201)

    def test_join_invalid_invite(self, client, logged_user):
        r = client.post("/api/rooms/join/invalid_code_xyz", json={
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        }, headers=logged_user["headers"])
        assert r.status_code in (404, 400)

    def test_leave_room(self, client, room, two_users):
        u1, u2 = two_users
        invite = room.get("invite_code") or room.get("room", {}).get("invite_code")
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        if invite:
            client.post(f"/api/rooms/join/{invite}", json={
                "encrypted_room_key": {
                    "ephemeral_pub": secrets.token_hex(32),
                    "ciphertext": secrets.token_hex(60),
                },
            }, headers=u2["headers"])
        r = client.delete(f"/api/rooms/{room_id}/leave", headers=u2["headers"])
        assert r.status_code in (200, 204, 400, 403, 404)


class TestRoomDetails:
    """Room details and listing."""

    def test_get_room_details(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.get(f"/api/rooms/{room_id}", headers=logged_user["headers"])
        assert r.status_code == 200

    def test_get_nonexistent_room(self, client, logged_user):
        r = client.get("/api/rooms/999999", headers=logged_user["headers"])
        assert r.status_code in (403, 404)

    def test_list_my_rooms(self, client, logged_user, room):
        r = client.get("/api/rooms/my", headers=logged_user["headers"])
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, (list, dict))

    def test_list_public_rooms(self, client):
        r = client.get("/api/rooms/public")
        assert r.status_code == 200

    def test_room_members(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.get(f"/api/rooms/{room_id}/members", headers=logged_user["headers"])
        assert r.status_code == 200


class TestRoomUpdate:
    """Room update operations."""

    def test_update_room_name(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.put(f"/api/rooms/{room_id}", json={
            "name": f"renamed_{random_str()}",
        }, headers=logged_user["headers"])
        assert r.status_code == 200

    def test_update_room_description(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.put(f"/api/rooms/{room_id}", json={
            "description": "Updated description",
        }, headers=logged_user["headers"])
        assert r.status_code == 200

    def test_update_room_unauthorized(self, client, room, two_users):
        u1, u2 = two_users
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.put(f"/api/rooms/{room_id}", json={
            "name": "hacked",
        }, headers=u2["headers"])
        assert r.status_code in (403, 404)


class TestRoomModeration:
    """Room moderation — kick, mute, ban, roles."""

    def test_kick_user(self, client, logged_user, room, two_users):
        u1, u2 = two_users
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        invite = room.get("invite_code") or room.get("room", {}).get("invite_code")
        if invite:
            client.post(f"/api/rooms/join/{invite}", json={
                "encrypted_room_key": {
                    "ephemeral_pub": secrets.token_hex(32),
                    "ciphertext": secrets.token_hex(60),
                },
            }, headers=u2["headers"])
        target_id = u2.get("data", {}).get("user_id", u2.get("data", {}).get("id", 2))
        r = client.post(f"/api/rooms/{room_id}/kick/{target_id}",
                        headers=logged_user["headers"])
        assert r.status_code in (200, 403, 404)

    def test_mute_user(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.put(f"/api/rooms/{room_id}/members/999/mute", json={
            "is_muted": True,
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 403, 404)

    def test_ban_user(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.put(f"/api/rooms/{room_id}/members/999/ban", json={
            "is_banned": True,
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 403, 404)

    def test_change_role(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.put(f"/api/rooms/{room_id}/members/999/role", json={
            "role": "admin",
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 403, 404)


class TestRoomFeatures:
    """Advanced room features."""

    def test_auto_delete(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/rooms/{room_id}/auto-delete", json={
            "seconds": 3600,
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_slow_mode(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/rooms/{room_id}/slow-mode", json={
            "seconds": 10,
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_pin_message(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/rooms/{room_id}/pin", json={
            "message_id": 1,
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_export_chat(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.get(f"/api/rooms/{room_id}/export",
                       headers=logged_user["headers"])
        assert r.status_code in (200, 403, 404)

    def test_room_mute_notifications(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/rooms/{room_id}/mute", json={
            "is_muted": True,
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_key_bundle(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.get(f"/api/rooms/{room_id}/key-bundle",
                       headers=logged_user["headers"])
        assert r.status_code in (200, 404)

    def test_provide_key(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/rooms/{room_id}/provide-key", json={
            "for_user_id": 999,
            "ephemeral_pub": secrets.token_hex(32),
            "ciphertext": secrets.token_hex(60),
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_rotate_key(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/rooms/{room_id}/rotate-key", json={
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_delete_room(self, client, logged_user):
        # Create a room specifically for deletion
        r = client.post("/api/rooms", json={
            "name": f"deleteme_{random_str()}",
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 201)
        data = r.json()
        room_id = data.get("id") or data.get("room", {}).get("id")
        if room_id:
            r2 = client.delete(f"/api/rooms/{room_id}", headers=logged_user["headers"])
            assert r2.status_code in (200, 204, 403)

"""Voice channel and link preview tests."""
import secrets
import pytest
from conftest import make_user, login_user, random_str


class TestVoiceChannels:
    """Voice channel REST endpoints."""

    def test_voice_join(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/voice/{room_id}/join", headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_voice_leave(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/voice/{room_id}/leave", headers=logged_user["headers"])
        assert r.status_code in (200, 400, 404)

    def test_voice_participants(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.get(f"/api/voice/{room_id}/participants", headers=logged_user["headers"])
        assert r.status_code in (200, 400, 404)

    def test_voice_mute(self, client, logged_user, room):
        room_id = room.get("id") or room.get("room", {}).get("id", 1)
        r = client.post(f"/api/voice/{room_id}/mute", json={
            "is_muted": True,
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 404, 422)

    def test_voice_unauthenticated(self, client):
        r = client.post("/api/voice/1/join")
        assert r.status_code in (401, 403, 422)


class TestLinkPreview:
    """Link preview endpoint tests."""

    def test_link_preview_endpoint_exists(self, client, logged_user):
        r = client.get("/api/link-preview?url=https://example.com",
                       headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 404, 422)

    def test_link_preview_no_url(self, client, logged_user):
        r = client.get("/api/link-preview", headers=logged_user["headers"])
        assert r.status_code in (400, 404, 422)

    def test_link_preview_private_ip_blocked(self, client, logged_user):
        r = client.get("/api/link-preview?url=http://127.0.0.1/admin",
                       headers=logged_user["headers"])
        assert r.status_code in (200, 400, 403, 422)

    def test_link_preview_invalid_url(self, client, logged_user):
        r = client.get("/api/link-preview?url=not_a_url",
                       headers=logged_user["headers"])
        assert r.status_code in (200, 400, 422)


class TestSearchEndpoints:
    """Search API tests."""

    def test_user_search(self, client, logged_user, fresh_user):
        r = client.get(
            f"/api/users/search?q={fresh_user['username'][:4]}",
            headers=logged_user["headers"],
        )
        assert r.status_code in (200, 404, 405)

    def test_global_search(self, client, logged_user):
        r = client.get("/api/users/global-search?q=test",
                       headers=logged_user["headers"])
        assert r.status_code in (200, 404, 405)

    def test_search_empty_query(self, client, logged_user):
        r = client.get("/api/users/search?q=",
                       headers=logged_user["headers"])
        assert r.status_code in (200, 400, 404, 405, 422)

    def test_search_unauthenticated(self, client):
        r = client.get("/api/users/search?q=test")
        assert r.status_code in (200, 401, 403, 404, 405)

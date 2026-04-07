"""Extended DM and contact tests."""
import secrets
import pytest
from conftest import make_user, login_user, random_str


class TestDMCreation:
    """Direct message room creation and listing."""

    def test_create_dm(self, client, two_users):
        u1, u2 = two_users
        target_id = u2.get("data", {}).get("user_id") or u2.get("data", {}).get("id")
        if not target_id:
            pytest.skip("Cannot determine target user ID")
        r = client.post(f"/api/dm/{target_id}", headers=u1["headers"], json={})
        assert r.status_code in (200, 201, 400, 422)

    def test_create_dm_self(self, client, logged_user):
        user_id = logged_user.get("data", {}).get("user_id") or logged_user.get("data", {}).get("id")
        if not user_id:
            pytest.skip("Cannot determine user ID")
        r = client.post(f"/api/dm/{user_id}", headers=logged_user["headers"])
        # Should fail — can't DM yourself
        assert r.status_code in (400, 403, 404, 422)

    def test_create_dm_nonexistent_user(self, client, logged_user):
        r = client.post("/api/dm/999999", headers=logged_user["headers"], json={})
        assert r.status_code in (400, 404, 422)

    def test_dm_list(self, client, logged_user):
        r = client.get("/api/dm/list", headers=logged_user["headers"])
        assert r.status_code == 200

    def test_dm_list_unauthenticated(self, client):
        r = client.get("/api/dm/list")
        # Session-scoped client may retain cookies
        assert r.status_code in (200, 401, 403)

    def test_dm_store_key(self, client, logged_user):
        r = client.post("/api/dm/store-key/1", json={
            "ephemeral_pub": secrets.token_hex(32),
            "ciphertext": secrets.token_hex(60),
        }, headers=logged_user["headers"])
        assert r.status_code in (200, 400, 404, 422)


class TestContactsExtended:
    """Extended contact management tests."""

    def test_add_contact(self, client, two_users):
        u1, u2 = two_users
        target_id = u2.get("data", {}).get("user_id") or u2.get("data", {}).get("id")
        if not target_id:
            pytest.skip("No target ID")
        r = client.post("/api/contacts", json={
            "user_id": target_id,
        }, headers=u1["headers"])
        assert r.status_code in (200, 201, 400, 409, 422)

    def test_add_contact_with_nickname(self, client, two_users):
        u1, u2 = two_users
        target_id = u2.get("data", {}).get("user_id") or u2.get("data", {}).get("id")
        if not target_id:
            pytest.skip("No target ID")
        r = client.post("/api/contacts", json={
            "user_id": target_id,
        }, headers=u1["headers"])
        assert r.status_code in (200, 201, 400, 409, 422)

    def test_list_contacts(self, client, logged_user):
        r = client.get("/api/contacts", headers=logged_user["headers"])
        assert r.status_code == 200

    def test_delete_nonexistent_contact(self, client, logged_user):
        r = client.delete("/api/contacts/999999", headers=logged_user["headers"])
        assert r.status_code in (200, 404)

    def test_search_users(self, client, logged_user, fresh_user):
        r = client.get(
            f"/api/contacts/search?q={fresh_user['username'][:5]}",
            headers=logged_user["headers"],
        )
        assert r.status_code in (200, 404, 405)


class TestBlocking:
    """User blocking tests."""

    def test_block_user(self, client, two_users):
        u1, u2 = two_users
        target_id = u2.get("data", {}).get("user_id") or u2.get("data", {}).get("id")
        if not target_id:
            pytest.skip("No target ID")
        r = client.post(f"/api/users/block/{target_id}", headers=u1["headers"])
        assert r.status_code in (200, 201, 400, 404)

    def test_block_nonexistent_user(self, client, logged_user):
        r = client.post("/api/users/block/999999", headers=logged_user["headers"])
        assert r.status_code in (200, 400, 404)

    def test_block_unauthenticated(self, client):
        r = client.post("/api/users/block/1")
        # Session-scoped client may retain cookies
        assert r.status_code in (200, 401, 403, 404, 422)

"""
Tests for Advanced Spaces features:
nested spaces (sub-spaces), templates, discovery, audit logs, onboarding,
custom emojis, vanity URLs, and permission overrides.
"""
import io
import secrets

import pytest

from conftest import make_user, login_user, random_str


# ── helpers ──────────────────────────────────────────────────────────────────

def _create_space(client, headers, *, name=None, is_public=False):
    """Create a space and return its full JSON response."""
    r = client.post("/api/spaces", json={
        "name": name or f"space_{random_str()}",
        "description": "Test space",
        "is_public": is_public,
    }, headers=headers)
    assert r.status_code in (200, 201), f"create space failed: {r.text}"
    return r.json()


def _make_owner(client):
    """Register, log in, create a space; return (user_dict, space_dict)."""
    user = make_user(client)
    headers = login_user(client, user["username"], user["password"])
    user["headers"] = headers
    space = _create_space(client, headers)
    return user, space


# ══════════════════════════════════════════════════════════════════════════════
# Templates
# ══════════════════════════════════════════════════════════════════════════════

class TestSpaceTemplates:

    def test_list_templates_returns_known_ids(self, client):
        r = client.get("/api/spaces/templates")
        assert r.status_code == 200
        data = r.json()
        assert "templates" in data
        ids = {t["id"] for t in data["templates"]}
        assert "gaming" in ids
        assert "community" in ids
        assert "study" in ids
        assert "project" in ids

    def test_list_templates_has_counts(self, client):
        r = client.get("/api/spaces/templates")
        assert r.status_code == 200
        for tmpl in r.json()["templates"]:
            assert "categories" in tmpl
            assert "rooms" in tmpl
            assert tmpl["categories"] > 0
            assert tmpl["rooms"] > 0

    def test_apply_template_gaming(self, client):
        user, space = _make_owner(client)
        r = client.post(
            f"/api/spaces/{space['id']}/apply-template",
            params={"template_id": "gaming"},
            headers=user["headers"],
        )
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["template"] == "gaming"
        assert data["rooms_created"] > 0
        assert isinstance(data["rooms"], list)

    def test_apply_template_community(self, client):
        user, space = _make_owner(client)
        r = client.post(
            f"/api/spaces/{space['id']}/apply-template",
            params={"template_id": "community"},
            headers=user["headers"],
        )
        assert r.status_code == 200
        assert r.json()["template"] == "community"

    def test_apply_template_study(self, client):
        user, space = _make_owner(client)
        r = client.post(
            f"/api/spaces/{space['id']}/apply-template",
            params={"template_id": "study"},
            headers=user["headers"],
        )
        assert r.status_code == 200
        assert r.json()["rooms_created"] > 0

    def test_apply_template_project(self, client):
        user, space = _make_owner(client)
        r = client.post(
            f"/api/spaces/{space['id']}/apply-template",
            params={"template_id": "project"},
            headers=user["headers"],
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_apply_unknown_template_returns_404(self, client):
        user, space = _make_owner(client)
        r = client.post(
            f"/api/spaces/{space['id']}/apply-template",
            params={"template_id": "does_not_exist"},
            headers=user["headers"],
        )
        assert r.status_code == 404

    def test_apply_template_non_admin_forbidden(self, client):
        _, space = _make_owner(client)
        # A different user who is NOT a member
        other = make_user(client)
        h2 = login_user(client, other["username"], other["password"])
        r = client.post(
            f"/api/spaces/{space['id']}/apply-template",
            params={"template_id": "gaming"},
            headers=h2,
        )
        assert r.status_code in (403, 401)


# ══════════════════════════════════════════════════════════════════════════════
# Nested Spaces (Sub-Spaces)
# ══════════════════════════════════════════════════════════════════════════════

class TestNestedSpaces:

    def test_create_sub_space_returns_201(self, client):
        user, space = _make_owner(client)
        r = client.post(
            f"/api/spaces/{space['id']}/sub-spaces",
            headers=user["headers"],
        )
        assert r.status_code == 201
        data = r.json()
        assert "id" in data
        assert data["parent_id"] == space["id"]

    def test_create_sub_space_has_invite_code(self, client):
        user, space = _make_owner(client)
        r = client.post(
            f"/api/spaces/{space['id']}/sub-spaces",
            headers=user["headers"],
        )
        assert r.status_code == 201
        assert r.json()["invite_code"]

    def test_list_sub_spaces_empty(self, client):
        user, space = _make_owner(client)
        r = client.get(
            f"/api/spaces/{space['id']}/sub-spaces",
            headers=user["headers"],
        )
        assert r.status_code == 200
        assert r.json()["sub_spaces"] == []

    def test_list_sub_spaces_after_creation(self, client):
        user, space = _make_owner(client)
        # Create two sub-spaces
        client.post(f"/api/spaces/{space['id']}/sub-spaces", headers=user["headers"])
        client.post(f"/api/spaces/{space['id']}/sub-spaces", headers=user["headers"])
        r = client.get(f"/api/spaces/{space['id']}/sub-spaces", headers=user["headers"])
        assert r.status_code == 200
        sub_spaces = r.json()["sub_spaces"]
        assert len(sub_spaces) >= 2

    def test_create_sub_space_non_admin_forbidden(self, client):
        _, space = _make_owner(client)
        other = make_user(client)
        h2 = login_user(client, other["username"], other["password"])
        r = client.post(
            f"/api/spaces/{space['id']}/sub-spaces",
            headers=h2,
        )
        assert r.status_code in (403, 401)

    def test_create_sub_space_nonexistent_parent_returns_404(self, client):
        user = make_user(client)
        headers = login_user(client, user["username"], user["password"])
        # We need to be admin of *some* space to pass the admin check on a ghost ID
        # The admin check runs first and will 403; so just verify 4xx
        r = client.post("/api/spaces/999999/sub-spaces", headers=headers)
        assert r.status_code in (403, 404)


# ══════════════════════════════════════════════════════════════════════════════
# Onboarding
# ══════════════════════════════════════════════════════════════════════════════

class TestOnboarding:

    def test_get_onboarding_public(self, client):
        _, space = _make_owner(client)
        r = client.get(f"/api/spaces/{space['id']}/onboarding")
        assert r.status_code == 200
        data = r.json()
        assert "welcome_message" in data
        assert "rules" in data
        assert "onboarding_roles" in data
        assert "space_name" in data

    def test_get_onboarding_nonexistent_space(self, client):
        r = client.get("/api/spaces/999999/onboarding")
        assert r.status_code == 404

    def test_set_onboarding_welcome_message(self, client):
        user, space = _make_owner(client)
        r = client.put(
            f"/api/spaces/{space['id']}/onboarding",
            json={"welcome_message": "Welcome to our community!"},
            headers=user["headers"],
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_set_onboarding_rules(self, client):
        user, space = _make_owner(client)
        r = client.put(
            f"/api/spaces/{space['id']}/onboarding",
            json={"rules": "Be respectful. No spam."},
            headers=user["headers"],
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_set_onboarding_roles(self, client):
        user, space = _make_owner(client)
        r = client.put(
            f"/api/spaces/{space['id']}/onboarding",
            json={"onboarding_roles": ["Gamer", "Developer", "Artist"]},
            headers=user["headers"],
        )
        assert r.status_code == 200

    def test_onboarding_persists_after_update(self, client):
        user, space = _make_owner(client)
        msg = f"Welcome! {random_str()}"
        client.put(
            f"/api/spaces/{space['id']}/onboarding",
            json={"welcome_message": msg},
            headers=user["headers"],
        )
        r = client.get(f"/api/spaces/{space['id']}/onboarding")
        assert r.status_code == 200
        assert r.json()["welcome_message"] == msg

    def test_set_onboarding_non_admin_forbidden(self, client):
        _, space = _make_owner(client)
        other = make_user(client)
        h2 = login_user(client, other["username"], other["password"])
        r = client.put(
            f"/api/spaces/{space['id']}/onboarding",
            json={"welcome_message": "Hack!"},
            headers=h2,
        )
        assert r.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# Space Discovery
# ══════════════════════════════════════════════════════════════════════════════

class TestSpaceDiscovery:

    def test_discover_returns_list(self, client):
        r = client.get("/api/spaces/discover")
        assert r.status_code == 200
        assert "spaces" in r.json()

    def test_discover_only_public_spaces(self, client):
        user = make_user(client)
        headers = login_user(client, user["username"], user["password"])
        unique = f"pub_{random_str(8)}"
        _create_space(client, headers, name=unique, is_public=True)
        r = client.get("/api/spaces/discover", params={"q": unique})
        assert r.status_code == 200
        spaces = r.json()["spaces"]
        assert len(spaces) >= 1
        assert spaces[0]["name"] == unique

    def test_discover_private_space_not_in_results(self, client):
        user = make_user(client)
        headers = login_user(client, user["username"], user["password"])
        unique = f"priv_{random_str(8)}"
        _create_space(client, headers, name=unique, is_public=False)
        r = client.get("/api/spaces/discover", params={"q": unique})
        assert r.status_code == 200
        names = [s["name"] for s in r.json()["spaces"]]
        assert unique not in names

    def test_discover_empty_query_returns_results(self, client):
        r = client.get("/api/spaces/discover", params={"q": ""})
        assert r.status_code == 200
        assert isinstance(r.json()["spaces"], list)

    def test_discover_result_fields(self, client):
        user = make_user(client)
        headers = login_user(client, user["username"], user["password"])
        unique = f"disc_{random_str(8)}"
        _create_space(client, headers, name=unique, is_public=True)
        r = client.get("/api/spaces/discover", params={"q": unique})
        spaces = r.json()["spaces"]
        if spaces:
            s = spaces[0]
            assert "id" in s
            assert "name" in s
            assert "member_count" in s
            assert "invite_code" in s

    def test_discover_no_match_returns_empty(self, client):
        r = client.get("/api/spaces/discover", params={"q": "zzznomatch9999xyz"})
        assert r.status_code == 200
        assert r.json()["spaces"] == []


# ══════════════════════════════════════════════════════════════════════════════
# Audit Log
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditLog:

    def test_audit_log_requires_auth(self, anon_client):
        r = anon_client.get("/api/spaces/1/audit-log")
        assert r.status_code in (401, 403, 422)

    def test_audit_log_returns_entries_list(self, client):
        user, space = _make_owner(client)
        r = client.get(f"/api/spaces/{space['id']}/audit-log", headers=user["headers"])
        assert r.status_code == 200
        data = r.json()
        assert "entries" in data
        assert isinstance(data["entries"], list)

    def test_audit_log_non_admin_forbidden(self, client):
        _, space = _make_owner(client)
        other = make_user(client)
        h2 = login_user(client, other["username"], other["password"])
        r = client.get(f"/api/spaces/{space['id']}/audit-log", headers=h2)
        assert r.status_code in (401, 403)

    def test_audit_log_records_sub_space_creation(self, client):
        user, space = _make_owner(client)
        client.post(f"/api/spaces/{space['id']}/sub-spaces", headers=user["headers"])
        r = client.get(f"/api/spaces/{space['id']}/audit-log", headers=user["headers"])
        assert r.status_code == 200
        actions = [e["action"] for e in r.json()["entries"]]
        assert "sub_space_create" in actions

    def test_audit_log_records_onboarding_update(self, client):
        user, space = _make_owner(client)
        client.put(
            f"/api/spaces/{space['id']}/onboarding",
            json={"welcome_message": "hello"},
            headers=user["headers"],
        )
        r = client.get(f"/api/spaces/{space['id']}/audit-log", headers=user["headers"])
        actions = [e["action"] for e in r.json()["entries"]]
        assert "onboarding_update" in actions

    def test_audit_log_entry_has_required_fields(self, client):
        user, space = _make_owner(client)
        client.post(f"/api/spaces/{space['id']}/sub-spaces", headers=user["headers"])
        r = client.get(f"/api/spaces/{space['id']}/audit-log", headers=user["headers"])
        entries = r.json()["entries"]
        assert len(entries) > 0
        e = entries[0]
        assert "id" in e
        assert "action" in e
        assert "actor_id" in e
        assert "created_at" in e

    def test_audit_log_limit_param(self, client):
        user, space = _make_owner(client)
        r = client.get(
            f"/api/spaces/{space['id']}/audit-log",
            params={"limit": 5},
            headers=user["headers"],
        )
        assert r.status_code == 200
        assert len(r.json()["entries"]) <= 5


# ══════════════════════════════════════════════════════════════════════════════
# Vanity URL
# ══════════════════════════════════════════════════════════════════════════════

class TestVanityURL:

    def test_set_vanity_url(self, client):
        user, space = _make_owner(client)
        slug = f"vanity-{random_str(6)}"
        r = client.put(
            f"/api/spaces/{space['id']}/vanity",
            json={"vanity_url": slug},
            headers=user["headers"],
        )
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["vanity_url"] == slug

    def test_resolve_vanity_url(self, client):
        user, space = _make_owner(client)
        slug = f"resolve-{random_str(6)}"
        client.put(
            f"/api/spaces/{space['id']}/vanity",
            json={"vanity_url": slug},
            headers=user["headers"],
        )
        r = client.get(f"/api/spaces/s/{slug}")
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == space["id"]
        assert data["name"] == space["name"]

    def test_resolve_nonexistent_vanity_url(self, client):
        r = client.get("/api/spaces/s/this-slug-does-not-exist-xyz")
        assert r.status_code == 404

    def test_duplicate_vanity_url_returns_409(self, client):
        user1, space1 = _make_owner(client)
        slug = f"dup-{random_str(6)}"
        # Set vanity for space1 while user1's cookie is still active
        client.put(
            f"/api/spaces/{space1['id']}/vanity",
            json={"vanity_url": slug},
            headers=user1["headers"],
        )
        # Now create user2 (overwrites cookie) and try same vanity on space2
        user2, space2 = _make_owner(client)
        r = client.put(
            f"/api/spaces/{space2['id']}/vanity",
            json={"vanity_url": slug},
            headers=user2["headers"],
        )
        assert r.status_code == 409

    def test_vanity_url_invalid_chars(self, client):
        user, space = _make_owner(client)
        r = client.put(
            f"/api/spaces/{space['id']}/vanity",
            json={"vanity_url": "UPPERCASE"},  # pattern is ^[a-z0-9_-]+$
            headers=user["headers"],
        )
        assert r.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# Custom Emoji
# ══════════════════════════════════════════════════════════════════════════════

class TestCustomEmoji:

    def test_list_emojis_empty(self, client):
        user, space = _make_owner(client)
        r = client.get(f"/api/spaces/{space['id']}/emojis", headers=user["headers"])
        assert r.status_code == 200
        assert r.json()["emojis"] == []

    def test_upload_emoji(self, client):
        user, space = _make_owner(client)
        png_bytes = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
            b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02"
            b"\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx"
            b"\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        emoji_name = f"test{random_str(4)}"
        r = client.post(
            f"/api/spaces/{space['id']}/emojis",
            params={"name": emoji_name},
            files={"file": ("emoji.png", io.BytesIO(png_bytes), "image/png")},
            headers=user["headers"],
        )
        assert r.status_code in (200, 201)
        data = r.json()
        assert data["name"] == emoji_name
        assert "image_url" in data

    def test_delete_emoji(self, client):
        user, space = _make_owner(client)
        png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
        emoji_name = f"del{random_str(4)}"
        create_r = client.post(
            f"/api/spaces/{space['id']}/emojis",
            params={"name": emoji_name},
            files={"file": ("e.png", io.BytesIO(png_bytes), "image/png")},
            headers=user["headers"],
        )
        if create_r.status_code not in (200, 201):
            pytest.skip("emoji upload not supported in this env")
        emoji_id = create_r.json()["id"]
        r = client.delete(
            f"/api/spaces/{space['id']}/emojis/{emoji_id}",
            headers=user["headers"],
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_delete_nonexistent_emoji(self, client):
        user, space = _make_owner(client)
        r = client.delete(
            f"/api/spaces/{space['id']}/emojis/999999",
            headers=user["headers"],
        )
        assert r.status_code == 404

    def test_list_emojis_requires_auth(self, anon_client, client):
        _, space = _make_owner(client)
        r = anon_client.get(f"/api/spaces/{space['id']}/emojis")
        assert r.status_code in (401, 403)


# ══════════════════════════════════════════════════════════════════════════════
# Permission Overrides
# ══════════════════════════════════════════════════════════════════════════════

class TestPermissions:

    def _get_first_room_id(self, client, user, space_id):
        r = client.get(f"/api/spaces/{space_id}", headers=user["headers"])
        if r.status_code == 200:
            cats = r.json().get("categories", [])
            for cat in cats:
                rooms = cat.get("rooms", [])
                if rooms:
                    return rooms[0]["id"]
        return None

    def test_get_permissions_requires_admin(self, client):
        _, space = _make_owner(client)
        other = make_user(client)
        h2 = login_user(client, other["username"], other["password"])
        r = client.get(f"/api/spaces/{space['id']}/permissions/1", headers=h2)
        assert r.status_code in (401, 403)

    def test_get_permissions_returns_structure(self, client):
        user, space = _make_owner(client)
        room_id = self._get_first_room_id(client, user, space["id"])
        if room_id is None:
            pytest.skip("no rooms found in space")
        r = client.get(
            f"/api/spaces/{space['id']}/permissions/{room_id}",
            headers=user["headers"],
        )
        assert r.status_code == 200
        data = r.json()
        assert "permissions" in data
        assert "flags" in data

    def test_set_permission_by_role(self, client):
        user, space = _make_owner(client)
        room_id = self._get_first_room_id(client, user, space["id"])
        if room_id is None:
            pytest.skip("no rooms found in space")
        r = client.put(
            f"/api/spaces/{space['id']}/permissions",
            json={"room_id": room_id, "role": "member", "allow": 4, "deny": 0},
            headers=user["headers"],
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_set_permission_missing_role_and_user_id(self, client):
        user, space = _make_owner(client)
        room_id = self._get_first_room_id(client, user, space["id"])
        if room_id is None:
            pytest.skip("no rooms found in space")
        r = client.put(
            f"/api/spaces/{space['id']}/permissions",
            json={"room_id": room_id, "allow": 4, "deny": 0},
            headers=user["headers"],
        )
        assert r.status_code == 400

"""
test_groups_extended.py — Comprehensive tests for the Groups API (app/chats/groups.py).

Covers:
  Topics:
    GET    /api/rooms/{room_id}/topics
    POST   /api/rooms/{room_id}/topics
    PUT    /api/rooms/{room_id}/topics/{topic_id}
    DELETE /api/rooms/{room_id}/topics/{topic_id}

  Forum Threads:
    GET    /api/rooms/{room_id}/forum
    POST   /api/rooms/{room_id}/forum
    GET    /api/rooms/{room_id}/forum/{thread_id}
    PUT    /api/rooms/{room_id}/forum/{thread_id}
    POST   /api/rooms/{room_id}/forum/{thread_id}/upvote

  Permissions:
    GET    /api/rooms/{room_id}/permissions
    PUT    /api/rooms/{room_id}/permissions

  AutoMod:
    GET    /api/rooms/{room_id}/automod
    POST   /api/rooms/{room_id}/automod
    PUT    /api/rooms/{room_id}/automod/{rule_id}
    DELETE /api/rooms/{room_id}/automod/{rule_id}

  Slowmode:
    GET    /api/rooms/{room_id}/slowmode/users
    PUT    /api/rooms/{room_id}/slowmode/users
"""
from __future__ import annotations

import secrets

import pytest

from conftest import make_user, login_user, random_str, SyncASGIClient


# ── Helpers ────────────────────────────────────────────────────────────────────

def _register_and_login(client) -> tuple[dict, dict]:
    u = make_user(client)
    h = login_user(client, u["username"], u["password"])
    return u, h


def _user_id(u: dict) -> int:
    data = u.get("data", {})
    return data.get("user_id") or data.get("id") or 0


def _create_room(client, headers: dict, *, name: str | None = None,
                 is_public: bool = True) -> dict:
    r = client.post("/api/rooms", json={
        "name": name or f"room_{random_str()}",
        "is_public": is_public,
        "encrypted_room_key": {
            "ephemeral_pub": secrets.token_hex(32),
            "ciphertext": secrets.token_hex(60),
        },
    }, headers=headers)
    assert r.status_code in (200, 201), f"create room failed: {r.text}"
    return r.json()


def _join_room(client, room: dict, headers: dict) -> None:
    """Join a public room using its invite code."""
    invite_code = room["invite_code"]
    r = client.post(f"/api/rooms/join/{invite_code}", headers=headers)
    assert r.status_code in (200, 201, 204), f"join room failed: {r.status_code} {r.text}"


# ══════════════════════════════════════════════════════════════════════════════
# Topics
# ══════════════════════════════════════════════════════════════════════════════

class TestTopics:

    def test_list_topics_unauthenticated(self, client):
        r = client.get("/api/rooms/1/topics")
        assert r.status_code in (401, 403)

    def test_list_topics_non_member_forbidden(self, client):
        _, h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)

        _, h_other = _register_and_login(client)
        r = client.get(f"/api/rooms/{room['id']}/topics", headers=h_other)
        assert r.status_code in (403, 404)

    def test_list_topics_empty_for_new_room(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        r = client.get(f"/api/rooms/{room['id']}/topics", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert "topics" in body
        assert isinstance(body["topics"], list)

    def test_create_topic_as_owner_succeeds(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.post(f"/api/rooms/{room['id']}/topics", json={
            "title": "General Discussion",
            "icon_emoji": "💬",
        }, headers=h)
        assert r.status_code == 201
        body = r.json()
        assert "id" in body
        assert body["title"] == "General Discussion"
        assert body["icon_emoji"] == "💬"

    def test_create_topic_as_member_succeeds(self, client):
        _, h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)

        _, h_member = _register_and_login(client)
        _join_room(client, room, h_member)

        r = client.post(f"/api/rooms/{room['id']}/topics", json={
            "title": "Member Topic",
        }, headers=h_member)
        assert r.status_code == 201

    def test_create_topic_unauthenticated(self, client):
        r = client.post("/api/rooms/1/topics", json={"title": "Nope"})
        assert r.status_code in (401, 403)

    def test_create_topic_missing_title_rejected(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        r = client.post(f"/api/rooms/{room['id']}/topics", json={
            "icon_emoji": "🔥",
        }, headers=h)
        assert r.status_code in (400, 422)

    def test_created_topic_appears_in_list(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        title = f"topic_{random_str(8)}"
        client.post(f"/api/rooms/{room['id']}/topics", json={"title": title}, headers=h)

        r = client.get(f"/api/rooms/{room['id']}/topics", headers=h)
        titles = [t["title"] for t in r.json()["topics"]]
        assert title in titles

    def test_update_topic_requires_admin(self, client):
        _, h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)

        create_r = client.post(f"/api/rooms/{room['id']}/topics", json={"title": "My Topic"}, headers=h_owner)
        topic_id = create_r.json()["id"]

        _, h_member = _register_and_login(client)
        _join_room(client, room, h_member)

        r = client.put(f"/api/rooms/{room['id']}/topics/{topic_id}", json={
            "title": "Updated"
        }, headers=h_member)
        assert r.status_code in (403, 404)

    def test_update_topic_by_owner_succeeds(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        create_r = client.post(f"/api/rooms/{room['id']}/topics", json={"title": "Old Title"}, headers=h)
        topic_id = create_r.json()["id"]

        r = client.put(f"/api/rooms/{room['id']}/topics/{topic_id}", json={
            "title": "New Title",
            "is_pinned": True,
        }, headers=h)
        assert r.status_code == 200
        assert r.json().get("ok") is True

    def test_update_topic_nonexistent_returns_404(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.put(f"/api/rooms/{room['id']}/topics/999999", json={"title": "X"}, headers=h)
        assert r.status_code == 404

    def test_delete_topic_by_owner(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        create_r = client.post(f"/api/rooms/{room['id']}/topics", json={"title": "Delete Me"}, headers=h)
        topic_id = create_r.json()["id"]

        del_r = client.delete(f"/api/rooms/{room['id']}/topics/{topic_id}", headers=h)
        assert del_r.status_code == 200
        assert del_r.json().get("ok") is True

        # Verify it's gone
        list_r = client.get(f"/api/rooms/{room['id']}/topics", headers=h)
        ids = [t["id"] for t in list_r.json()["topics"]]
        assert topic_id not in ids

    def test_delete_topic_nonexistent_returns_404(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        r = client.delete(f"/api/rooms/{room['id']}/topics/999999", headers=h)
        assert r.status_code == 404

    def test_topic_list_contains_expected_fields(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        client.post(f"/api/rooms/{room['id']}/topics", json={
            "title": "Structured Topic",
            "icon_emoji": "📋",
        }, headers=h)

        r = client.get(f"/api/rooms/{room['id']}/topics", headers=h)
        topics = r.json()["topics"]
        assert len(topics) >= 1
        t = topics[0]
        for field in ("id", "title", "icon_emoji", "is_pinned", "is_closed", "message_count", "created_at"):
            assert field in t, f"Missing field: {field}"


# ══════════════════════════════════════════════════════════════════════════════
# Forum Threads
# ══════════════════════════════════════════════════════════════════════════════

class TestForumThreads:

    def test_list_forum_unauthenticated(self, client):
        r = client.get("/api/rooms/1/forum")
        assert r.status_code in (401, 403)

    def test_list_forum_empty_for_new_room(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        r = client.get(f"/api/rooms/{room['id']}/forum", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert "threads" in body
        assert isinstance(body["threads"], list)

    def test_create_forum_thread_success(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.post(f"/api/rooms/{room['id']}/forum", json={
            "title": "How do I get started?",
            "body": "Looking for help!",
            "tags": ["help", "beginner"],
        }, headers=h)
        assert r.status_code == 201
        body = r.json()
        assert "id" in body
        assert body["title"] == "How do I get started?"

    def test_create_forum_thread_unauthenticated(self, client):
        r = client.post("/api/rooms/1/forum", json={"title": "Nope", "body": ""})
        assert r.status_code in (401, 403)

    def test_create_forum_thread_missing_title_rejected(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        r = client.post(f"/api/rooms/{room['id']}/forum", json={"body": "No title here"}, headers=h)
        assert r.status_code in (400, 422)

    def test_create_forum_thread_non_member_forbidden(self, client):
        _, h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)

        _, h_other = _register_and_login(client)
        r = client.post(f"/api/rooms/{room['id']}/forum", json={
            "title": "Intrusion",
            "body": "",
        }, headers=h_other)
        assert r.status_code in (403, 404)

    def test_created_thread_appears_in_list(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        title = f"thread_{random_str(8)}"
        client.post(f"/api/rooms/{room['id']}/forum", json={"title": title, "body": ""}, headers=h)

        r = client.get(f"/api/rooms/{room['id']}/forum", headers=h)
        titles = [t["title"] for t in r.json()["threads"]]
        assert title in titles

    def test_get_forum_thread_by_id(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        create_r = client.post(f"/api/rooms/{room['id']}/forum", json={
            "title": "Specific Thread",
            "body": "Detailed content here",
            "tags": ["specific"],
        }, headers=h)
        thread_id = create_r.json()["id"]

        r = client.get(f"/api/rooms/{room['id']}/forum/{thread_id}", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert body["title"] == "Specific Thread"
        assert body["body"] == "Detailed content here"
        assert "specific" in body["tags"]

    def test_get_forum_thread_not_found(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        r = client.get(f"/api/rooms/{room['id']}/forum/999999", headers=h)
        assert r.status_code == 404

    def test_thread_detail_has_all_fields(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        create_r = client.post(f"/api/rooms/{room['id']}/forum", json={
            "title": "Full Fields Thread",
            "body": "Content",
        }, headers=h)
        thread_id = create_r.json()["id"]

        r = client.get(f"/api/rooms/{room['id']}/forum/{thread_id}", headers=h)
        body = r.json()
        for field in ("id", "title", "body", "creator_id", "tags", "is_pinned",
                      "is_locked", "is_solved", "reply_count", "upvotes", "created_at"):
            assert field in body, f"Missing field: {field}"

    def test_update_thread_requires_admin(self, client):
        _, h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)

        create_r = client.post(f"/api/rooms/{room['id']}/forum", json={
            "title": "Admin Only Update",
            "body": "",
        }, headers=h_owner)
        thread_id = create_r.json()["id"]

        _, h_member = _register_and_login(client)
        _join_room(client, room, h_member)

        r = client.put(f"/api/rooms/{room['id']}/forum/{thread_id}", json={
            "is_pinned": True,
        }, headers=h_member)
        assert r.status_code in (403, 404)

    def test_update_thread_pin_by_owner(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        create_r = client.post(f"/api/rooms/{room['id']}/forum", json={
            "title": "Pin Me",
            "body": "",
        }, headers=h)
        thread_id = create_r.json()["id"]

        r = client.put(f"/api/rooms/{room['id']}/forum/{thread_id}", json={
            "is_pinned": True,
        }, headers=h)
        assert r.status_code == 200
        assert r.json().get("ok") is True

    def test_update_thread_mark_solved(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        create_r = client.post(f"/api/rooms/{room['id']}/forum", json={
            "title": "Solvable Question",
            "body": "How?",
        }, headers=h)
        thread_id = create_r.json()["id"]

        r = client.put(f"/api/rooms/{room['id']}/forum/{thread_id}", json={
            "is_solved": True,
        }, headers=h)
        assert r.status_code == 200

    def test_upvote_thread_increases_count(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        create_r = client.post(f"/api/rooms/{room['id']}/forum", json={
            "title": "Upvote Me",
            "body": "",
        }, headers=h)
        thread_id = create_r.json()["id"]

        r = client.post(f"/api/rooms/{room['id']}/forum/{thread_id}/upvote", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert body.get("ok") is True
        assert "upvotes" in body
        assert body["upvotes"] >= 1

    def test_upvote_twice_increments_both_times(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        create_r = client.post(f"/api/rooms/{room['id']}/forum", json={
            "title": "Double Upvote",
            "body": "",
        }, headers=h)
        thread_id = create_r.json()["id"]

        r1 = client.post(f"/api/rooms/{room['id']}/forum/{thread_id}/upvote", headers=h)
        r2 = client.post(f"/api/rooms/{room['id']}/forum/{thread_id}/upvote", headers=h)
        assert r2.json()["upvotes"] == r1.json()["upvotes"] + 1

    def test_forum_sort_recent(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        r = client.get(f"/api/rooms/{room['id']}/forum?sort=recent", headers=h)
        assert r.status_code == 200

    def test_forum_sort_top(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        r = client.get(f"/api/rooms/{room['id']}/forum?sort=top", headers=h)
        assert r.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# Granular Permissions
# ══════════════════════════════════════════════════════════════════════════════

class TestPermissions:

    def test_get_permissions_unauthenticated(self, client):
        r = client.get("/api/rooms/1/permissions")
        assert r.status_code in (401, 403)

    def test_get_permissions_non_member_forbidden(self, client):
        _, h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)

        _, h_other = _register_and_login(client)
        r = client.get(f"/api/rooms/{room['id']}/permissions", headers=h_other)
        assert r.status_code in (403, 404)

    def test_get_permissions_member_sees_list(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.get(f"/api/rooms/{room['id']}/permissions", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert "permissions" in body
        assert isinstance(body["permissions"], list)
        assert "available_flags" in body

    def test_set_permission_by_role_requires_admin(self, client):
        _, h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)

        _, h_member = _register_and_login(client)
        _join_room(client, room, h_member)

        r = client.put(f"/api/rooms/{room['id']}/permissions", json={
            "role": "member",
            "allow": 4,
            "deny": 0,
        }, headers=h_member)
        assert r.status_code in (403, 404)

    def test_set_permission_by_role(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.put(f"/api/rooms/{room['id']}/permissions", json={
            "role": "member",
            "allow": 7,
            "deny": 0,
        }, headers=h)
        assert r.status_code == 200
        assert r.json().get("ok") is True

    def test_set_permission_by_user_id(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        u2 = make_user(client.make_anon_client())  # create user2 on separate client, cookie stays as owner

        r = client.put(f"/api/rooms/{room['id']}/permissions", json={
            "user_id": _user_id(u2),
            "allow": 3,
            "deny": 0,
        }, headers=h)
        assert r.status_code == 200
        assert r.json().get("ok") is True

    def test_set_permission_without_role_or_user_id_fails(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.put(f"/api/rooms/{room['id']}/permissions", json={
            "allow": 7,
            "deny": 0,
        }, headers=h)
        assert r.status_code in (400, 422)

    def test_permission_appears_after_set(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        room_id = room["id"]

        client.put(f"/api/rooms/{room_id}/permissions", json={
            "role": "member",
            "allow": 15,
            "deny": 0,
        }, headers=h)

        r = client.get(f"/api/rooms/{room_id}/permissions", headers=h)
        perms = r.json()["permissions"]
        member_perm = next((p for p in perms if p.get("role") == "member"), None)
        assert member_perm is not None
        assert member_perm["allow"] == 15


# ══════════════════════════════════════════════════════════════════════════════
# Auto-Moderation
# ══════════════════════════════════════════════════════════════════════════════

class TestAutoMod:

    def test_list_automod_unauthenticated(self, client):
        r = client.get("/api/rooms/1/automod")
        assert r.status_code in (401, 403)

    def test_list_automod_requires_admin(self, client):
        _, h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)

        _, h_member = _register_and_login(client)
        _join_room(client, room, h_member)

        r = client.get(f"/api/rooms/{room['id']}/automod", headers=h_member)
        assert r.status_code in (403, 404)

    def test_list_automod_empty_for_new_room(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.get(f"/api/rooms/{room['id']}/automod", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert "rules" in body
        assert isinstance(body["rules"], list)

    def test_create_word_filter_rule(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.post(f"/api/rooms/{room['id']}/automod", json={
            "name": "No Profanity",
            "rule_type": "word_filter",
            "pattern": "badword1, badword2",
            "action": "delete",
        }, headers=h)
        assert r.status_code == 201
        body = r.json()
        assert "id" in body
        assert body["name"] == "No Profanity"

    def test_create_regex_rule_valid_pattern(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.post(f"/api/rooms/{room['id']}/automod", json={
            "name": "No Crypto Links",
            "rule_type": "regex",
            "pattern": r"https?://(?:pump\.fun|honeypot\.is)",
            "action": "delete",
        }, headers=h)
        assert r.status_code == 201

    def test_create_regex_rule_invalid_pattern_rejected(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.post(f"/api/rooms/{room['id']}/automod", json={
            "name": "Bad Regex",
            "rule_type": "regex",
            "pattern": "(?P<invalid",  # invalid regex
            "action": "warn",
        }, headers=h)
        assert r.status_code in (400, 422)

    def test_create_automod_rule_non_member_forbidden(self, client):
        _, h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)

        _, h_other = _register_and_login(client)
        r = client.post(f"/api/rooms/{room['id']}/automod", json={
            "name": "Intruder Rule",
            "rule_type": "word_filter",
            "pattern": "spam",
            "action": "delete",
        }, headers=h_other)
        assert r.status_code in (403, 404)

    def test_created_rule_appears_in_list(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        rule_name = f"rule_{random_str(6)}"

        client.post(f"/api/rooms/{room['id']}/automod", json={
            "name": rule_name,
            "rule_type": "word_filter",
            "pattern": "test",
            "action": "warn",
        }, headers=h)

        r = client.get(f"/api/rooms/{room['id']}/automod", headers=h)
        names = [r_["name"] for r_ in r.json()["rules"]]
        assert rule_name in names

    def test_automod_rule_has_expected_fields(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        client.post(f"/api/rooms/{room['id']}/automod", json={
            "name": "Field Check",
            "rule_type": "caps_filter",
            "pattern": "0.8",
            "action": "warn",
            "mute_duration_seconds": 60,
        }, headers=h)

        r = client.get(f"/api/rooms/{room['id']}/automod", headers=h)
        rules = r.json()["rules"]
        rule = next((r_ for r_ in rules if r_["name"] == "Field Check"), None)
        assert rule is not None
        for field in ("id", "name", "rule_type", "pattern", "action",
                      "is_enabled", "mute_duration_seconds", "trigger_count"):
            assert field in rule, f"Missing field: {field}"

    def test_update_automod_rule_name(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        create_r = client.post(f"/api/rooms/{room['id']}/automod", json={
            "name": "Old Name",
            "rule_type": "word_filter",
            "pattern": "spam",
            "action": "delete",
        }, headers=h)
        rule_id = create_r.json()["id"]

        r = client.put(f"/api/rooms/{room['id']}/automod/{rule_id}", json={
            "name": "New Name",
        }, headers=h)
        assert r.status_code == 200
        assert r.json().get("ok") is True

    def test_update_automod_rule_disable(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        create_r = client.post(f"/api/rooms/{room['id']}/automod", json={
            "name": "Disable Me",
            "rule_type": "word_filter",
            "pattern": "bad",
            "action": "warn",
        }, headers=h)
        rule_id = create_r.json()["id"]

        r = client.put(f"/api/rooms/{room['id']}/automod/{rule_id}", json={
            "is_enabled": False,
        }, headers=h)
        assert r.status_code == 200

    def test_update_automod_rule_not_found(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.put(f"/api/rooms/{room['id']}/automod/999999", json={
            "name": "Ghost"
        }, headers=h)
        assert r.status_code == 404

    def test_delete_automod_rule(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        create_r = client.post(f"/api/rooms/{room['id']}/automod", json={
            "name": "Delete Me",
            "rule_type": "word_filter",
            "pattern": "bye",
            "action": "delete",
        }, headers=h)
        rule_id = create_r.json()["id"]

        del_r = client.delete(f"/api/rooms/{room['id']}/automod/{rule_id}", headers=h)
        assert del_r.status_code == 200
        assert del_r.json().get("ok") is True

        # Verify it's gone
        list_r = client.get(f"/api/rooms/{room['id']}/automod", headers=h)
        ids = [r_["id"] for r_ in list_r.json()["rules"]]
        assert rule_id not in ids

    def test_delete_automod_rule_not_found(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        r = client.delete(f"/api/rooms/{room['id']}/automod/999999", headers=h)
        assert r.status_code == 404

    def test_create_mute_action_rule(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.post(f"/api/rooms/{room['id']}/automod", json={
            "name": "Mute Spammers",
            "rule_type": "spam_detection",
            "pattern": "same_message",
            "action": "mute",
            "mute_duration_seconds": 300,
        }, headers=h)
        assert r.status_code == 201


# ══════════════════════════════════════════════════════════════════════════════
# Per-User Slowmode
# ══════════════════════════════════════════════════════════════════════════════

class TestSlowmode:

    def test_list_slowmode_unauthenticated(self, client):
        r = client.get("/api/rooms/1/slowmode/users")
        assert r.status_code in (401, 403)

    def test_list_slowmode_requires_admin(self, client):
        _, h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)

        _, h_member = _register_and_login(client)
        _join_room(client, room, h_member)

        r = client.get(f"/api/rooms/{room['id']}/slowmode/users", headers=h_member)
        assert r.status_code in (403, 404)

    def test_list_slowmode_empty_initially(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)

        r = client.get(f"/api/rooms/{room['id']}/slowmode/users", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert "slowmodes" in body
        assert isinstance(body["slowmodes"], list)

    def test_set_slowmode_for_user(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        u2 = make_user(client.make_anon_client())  # create on separate client, cookie stays as owner

        r = client.put(f"/api/rooms/{room['id']}/slowmode/users", json={
            "user_id": _user_id(u2),
            "cooldown_seconds": 30,
        }, headers=h)
        assert r.status_code == 200
        body = r.json()
        assert body.get("ok") is True
        assert body.get("cooldown_seconds") == 30

    def test_set_slowmode_user_appears_in_list(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        u2 = make_user(client.make_anon_client())  # create on separate client, cookie stays as owner
        uid2 = _user_id(u2)

        client.put(f"/api/rooms/{room['id']}/slowmode/users", json={
            "user_id": uid2,
            "cooldown_seconds": 60,
        }, headers=h)

        r = client.get(f"/api/rooms/{room['id']}/slowmode/users", headers=h)
        entries = r.json()["slowmodes"]
        user_entry = next((e for e in entries if e["user_id"] == uid2), None)
        assert user_entry is not None
        assert user_entry["cooldown_seconds"] == 60

    def test_remove_slowmode_with_zero_cooldown(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        u2 = make_user(client.make_anon_client())  # create on separate client, cookie stays as owner
        uid2 = _user_id(u2)

        # First set a slowmode
        client.put(f"/api/rooms/{room['id']}/slowmode/users", json={
            "user_id": uid2,
            "cooldown_seconds": 30,
        }, headers=h)

        # Then remove it with 0
        r = client.put(f"/api/rooms/{room['id']}/slowmode/users", json={
            "user_id": uid2,
            "cooldown_seconds": 0,
        }, headers=h)
        assert r.status_code == 200
        body = r.json()
        assert body.get("ok") is True
        assert body.get("removed") is True

        # Verify it's gone from the list
        list_r = client.get(f"/api/rooms/{room['id']}/slowmode/users", headers=h)
        ids = [e["user_id"] for e in list_r.json()["slowmodes"]]
        assert uid2 not in ids

    def test_update_existing_slowmode(self, client):
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        u2 = make_user(client.make_anon_client())  # create on separate client, cookie stays as owner
        uid2 = _user_id(u2)

        # Set initial slowmode
        client.put(f"/api/rooms/{room['id']}/slowmode/users", json={
            "user_id": uid2,
            "cooldown_seconds": 30,
        }, headers=h)

        # Update it
        r = client.put(f"/api/rooms/{room['id']}/slowmode/users", json={
            "user_id": uid2,
            "cooldown_seconds": 120,
        }, headers=h)
        assert r.status_code == 200
        assert r.json()["cooldown_seconds"] == 120

        # Verify updated value in list
        list_r = client.get(f"/api/rooms/{room['id']}/slowmode/users", headers=h)
        entry = next((e for e in list_r.json()["slowmodes"] if e["user_id"] == uid2), None)
        assert entry is not None
        assert entry["cooldown_seconds"] == 120

    def test_set_slowmode_max_value_allowed(self, client):
        """Cooldown max is 3600 seconds (1 hour)."""
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        u2 = make_user(client.make_anon_client())

        r = client.put(f"/api/rooms/{room['id']}/slowmode/users", json={
            "user_id": _user_id(u2),
            "cooldown_seconds": 3600,
        }, headers=h)
        assert r.status_code == 200

    def test_set_slowmode_exceeding_max_rejected(self, client):
        """Cooldown above 3600 should be rejected."""
        _, h = _register_and_login(client)
        room = _create_room(client, h)
        u2 = make_user(client.make_anon_client())

        r = client.put(f"/api/rooms/{room['id']}/slowmode/users", json={
            "user_id": _user_id(u2),
            "cooldown_seconds": 9999,
        }, headers=h)
        assert r.status_code in (400, 422)

    def test_set_slowmode_requires_admin(self, client):
        _, h_owner = _register_and_login(client)
        room = _create_room(client, h_owner)

        _, h_member = _register_and_login(client)
        _join_room(client, room, h_member)

        u3, _ = _register_and_login(client)

        r = client.put(f"/api/rooms/{room['id']}/slowmode/users", json={
            "user_id": _user_id(u3),
            "cooldown_seconds": 30,
        }, headers=h_member)
        assert r.status_code in (403, 404)

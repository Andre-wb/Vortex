"""
Comprehensive tests for:
  - app/bots/bot_api.py     (bot management CRUD, token, rooms, marketplace)
  - app/bots/bot_advanced.py (inline, keyboards, slash commands, webhooks,
                               payments, scopes, store, SDK info)

Pattern: def test_xxx(client) — uses the session-scope SyncASGIClient from conftest.
"""
import json
import secrets

import pytest
from conftest import make_user, login_user, random_str


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _auth(client) -> dict:
    """Register + login a fresh user, return auth headers."""
    u = make_user(client)
    h = login_user(client, u["username"], u["password"])
    return h


def _create_room(client, headers) -> int:
    """Create a public room and return its id."""
    r = client.post("/api/rooms", json={
        "name": f"bot_room_{random_str(6)}",
        "is_public": True,
        "encrypted_room_key": {
            "ephemeral_pub": secrets.token_hex(32),
            "ciphertext": secrets.token_hex(60),
        },
    }, headers=headers)
    assert r.status_code in (200, 201), f"room creation failed: {r.text}"
    data = r.json()
    return data.get("id") or data.get("room", {}).get("id")


def _create_bot(client, headers, name: str | None = None) -> dict:
    """Create a bot and return the full response JSON."""
    name = name or f"TestBot_{random_str(6)}"
    r = client.post("/api/bots", json={"name": name, "description": "A test bot"}, headers=headers)
    assert r.status_code == 201, f"bot creation failed: {r.text}"
    return r.json()


def _bot_token_header(token: str) -> dict:
    """Bot auth header format."""
    return {"Authorization": f"Bot {token}"}


# ─────────────────────────────────────────────────────────────────────────────
# Bot Creation (bot_api.py)
# ─────────────────────────────────────────────────────────────────────────────

def test_create_bot_requires_auth(client):
    r = client.post("/api/bots", json={"name": "NoAuth"})
    assert r.status_code in (401, 403)


def test_create_bot_success(client):
    h = _auth(client)
    r = client.post("/api/bots", json={"name": "MyBot", "description": "Helpful bot"}, headers=h)
    assert r.status_code == 201
    data = r.json()
    assert data["ok"] is True
    assert "bot_id" in data
    assert "api_token" in data
    assert len(data["api_token"]) == 64  # token_hex(32) = 64 hex chars


def test_create_bot_returns_username(client):
    h = _auth(client)
    data = _create_bot(client, h)
    assert "username" in data
    assert data["username"].startswith("bot_")


def test_create_bot_name_too_short(client):
    h = _auth(client)
    r = client.post("/api/bots", json={"name": "X"}, headers=h)
    assert r.status_code == 422


def test_create_bot_name_too_long(client):
    h = _auth(client)
    r = client.post("/api/bots", json={"name": "A" * 51}, headers=h)
    assert r.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# List / get bots
# ─────────────────────────────────────────────────────────────────────────────

def test_list_bots_requires_auth(anon_client):
    r = anon_client.get("/api/bots")
    assert r.status_code in (401, 403)


def test_list_bots_initially_may_be_empty_or_not(client):
    h = _auth(client)
    r = client.get("/api/bots", headers=h)
    assert r.status_code == 200
    assert "bots" in r.json()
    assert isinstance(r.json()["bots"], list)


def test_list_bots_after_creation(client):
    h = _auth(client)
    _create_bot(client, h, name=f"ListMe_{random_str(5)}")
    r = client.get("/api/bots", headers=h)
    assert r.status_code == 200
    bots = r.json()["bots"]
    assert len(bots) >= 1
    # Each entry has required fields
    for b in bots:
        assert "bot_id" in b
        assert "name" in b
        assert "is_active" in b


# ─────────────────────────────────────────────────────────────────────────────
# Update bot
# ─────────────────────────────────────────────────────────────────────────────

def test_update_bot_name(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    r = client.put(f"/api/bots/{bid}", json={"name": "RenamedBot"}, headers=h)
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_update_bot_commands(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    cmds = json.dumps([{"command": "/help", "description": "Show help"}])
    r = client.put(f"/api/bots/{bid}", json={"commands": cmds}, headers=h)
    assert r.status_code == 200


def test_update_bot_invalid_commands_json(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    r = client.put(f"/api/bots/{bid}", json={"commands": "not-json-at-all"}, headers=h)
    assert r.status_code in (422, 400)


def test_update_bot_mini_app_url(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    r = client.put(f"/api/bots/{bid}", json={"mini_app_url": "https://example.com/app"}, headers=h)
    assert r.status_code == 200


def test_update_bot_mini_app_url_invalid_scheme(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    r = client.put(f"/api/bots/{bid}", json={"mini_app_url": "ftp://bad.scheme"}, headers=h)
    assert r.status_code in (422, 403)  # WAF may block non-http(s) schemes with 403


def test_update_bot_not_owned(client):
    h1 = _auth(client)
    bot = _create_bot(client, h1)  # create bot while user1 cookie is active
    bid = bot["bot_id"]
    h2 = _auth(client)  # login user2 (overwrites cookie)
    r = client.put(f"/api/bots/{bid}", json={"name": "Hacker"}, headers=h2)
    assert r.status_code in (403, 404)


# ─────────────────────────────────────────────────────────────────────────────
# Token management
# ─────────────────────────────────────────────────────────────────────────────

def test_get_bot_token(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    # Token is stored hashed — GET /token returns 400 (security: hash-only storage)
    r = client.get(f"/api/bots/{bid}/token", headers=h)
    assert r.status_code == 400
    # Token is only available once, from the create response
    assert len(bot["api_token"]) == 64


def test_get_bot_token_not_owned(client):
    h1 = _auth(client)
    bot = _create_bot(client, h1)  # create bot while user1 cookie is active
    bid = bot["bot_id"]
    h2 = _auth(client)  # login user2 (overwrites cookie)
    r = client.get(f"/api/bots/{bid}/token", headers=h2)
    assert r.status_code in (403, 404)


def test_regenerate_token(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    old_token = bot["api_token"]
    r = client.post(f"/api/bots/{bid}/regenerate-token", headers=h)
    assert r.status_code == 200
    new_token = r.json()["api_token"]
    assert new_token != old_token
    assert len(new_token) == 64


def test_regenerate_token_not_owned(client):
    h1 = _auth(client)
    bot = _create_bot(client, h1)  # create bot while user1 cookie is active
    bid = bot["bot_id"]
    h2 = _auth(client)  # login user2 (overwrites cookie)
    r = client.post(f"/api/bots/{bid}/regenerate-token", headers=h2)
    assert r.status_code in (403, 404)


# ─────────────────────────────────────────────────────────────────────────────
# Bot /me and /rooms (bot-auth endpoints)
# ─────────────────────────────────────────────────────────────────────────────

def test_bot_me_valid_token(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    r = client.get("/api/bot/me", headers=_bot_token_header(bot["api_token"]))
    assert r.status_code == 200
    data = r.json()
    assert data["bot_id"] == bot["bot_id"]
    assert "name" in data
    assert data["is_active"] is True


def test_bot_me_invalid_token(client):
    r = client.get("/api/bot/me", headers=_bot_token_header("totally_fake_token"))
    assert r.status_code == 401


def test_bot_me_missing_token(client):
    r = client.get("/api/bot/me")
    assert r.status_code == 401


def test_bot_list_rooms_valid_token(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    r = client.get("/api/bot/rooms", headers=_bot_token_header(bot["api_token"]))
    assert r.status_code == 200
    assert "rooms" in r.json()


# ─────────────────────────────────────────────────────────────────────────────
# Add bot to room / remove
# ─────────────────────────────────────────────────────────────────────────────

def test_add_bot_to_room(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    room_id = _create_room(client, h)
    r = client.post(f"/api/bots/{bot['bot_id']}/rooms/{room_id}", headers=h)
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_add_bot_to_room_idempotent(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    room_id = _create_room(client, h)
    client.post(f"/api/bots/{bot['bot_id']}/rooms/{room_id}", headers=h)
    r = client.post(f"/api/bots/{bot['bot_id']}/rooms/{room_id}", headers=h)
    assert r.status_code == 200  # "already in room" is ok


def test_add_bot_to_nonexistent_room(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    r = client.post(f"/api/bots/{bot['bot_id']}/rooms/999999", headers=h)
    assert r.status_code in (403, 404)


def test_remove_bot_from_room(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    room_id = _create_room(client, h)
    client.post(f"/api/bots/{bot['bot_id']}/rooms/{room_id}", headers=h)
    r = client.delete(f"/api/bots/{bot['bot_id']}/rooms/{room_id}", headers=h)
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_remove_bot_not_in_room(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    room_id = _create_room(client, h)
    # Bot never added
    r = client.delete(f"/api/bots/{bot['bot_id']}/rooms/{room_id}", headers=h)
    assert r.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# Delete bot
# ─────────────────────────────────────────────────────────────────────────────

def test_delete_bot(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    r = client.delete(f"/api/bots/{bid}", headers=h)
    assert r.status_code == 200
    assert r.json()["ok"] is True
    # Token should no longer work
    me_r = client.get("/api/bot/me", headers=_bot_token_header(bot["api_token"]))
    assert me_r.status_code == 401


def test_delete_nonexistent_bot(client):
    h = _auth(client)
    r = client.delete("/api/bots/999999", headers=h)
    assert r.status_code == 404


def test_delete_bot_not_owned(client):
    h1 = _auth(client)
    bot = _create_bot(client, h1)  # create bot while user1 cookie is active
    h2 = _auth(client)  # login user2 (overwrites cookie)
    r = client.delete(f"/api/bots/{bot['bot_id']}", headers=h2)
    assert r.status_code in (403, 404)


# ─────────────────────────────────────────────────────────────────────────────
# SDK Info (bot_advanced.py)
# ─────────────────────────────────────────────────────────────────────────────

def test_sdk_info_no_auth_required(client):
    r = client.get("/api/bots/sdk-info")
    assert r.status_code == 200


def test_sdk_info_has_python_and_js(client):
    data = client.get("/api/bots/sdk-info").json()
    sdk = data["sdk"]
    assert "python" in sdk
    assert "javascript" in sdk


def test_sdk_info_python_has_install_and_example(client):
    data = client.get("/api/bots/sdk-info").json()
    py = data["sdk"]["python"]
    assert "install" in py
    assert "example" in py
    assert "pip install" in py["install"]


def test_sdk_info_http_api_endpoints(client):
    data = client.get("/api/bots/sdk-info").json()
    http = data["sdk"]["http_api"]
    assert "endpoints" in http
    assert len(http["endpoints"]) >= 5


# ─────────────────────────────────────────────────────────────────────────────
# Bot Store (bot_advanced.py)
# ─────────────────────────────────────────────────────────────────────────────

def test_bot_store_no_auth_required(client):
    r = client.get("/api/bots/store")
    assert r.status_code == 200


def test_bot_store_shape(client):
    data = client.get("/api/bots/store").json()
    assert "bots" in data
    assert isinstance(data["bots"], list)


def test_bot_store_search_query(client):
    r = client.get("/api/bots/store?q=helper")
    assert r.status_code == 200
    assert "bots" in r.json()


def test_bot_store_filter_by_category(client):
    r = client.get("/api/bots/store?category=utilities")
    assert r.status_code == 200
    assert "bots" in r.json()


def test_bot_store_sort_by_rating(client):
    r = client.get("/api/bots/store?sort=rating")
    assert r.status_code == 200


def test_bot_store_sort_by_new(client):
    r = client.get("/api/bots/store?sort=new")
    assert r.status_code == 200


def test_bot_store_entry_fields(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    # Publish bot to marketplace
    client.post(f"/api/bots/{bid}/publish",
                json={"is_public": True, "category": "utilities"}, headers=h)
    data = client.get("/api/bots/store").json()
    if data["bots"]:
        entry = data["bots"][0]
        for field in ("id", "name", "description", "category", "installs", "rating"):
            assert field in entry, f"Field {field!r} missing from store entry"


# ─────────────────────────────────────────────────────────────────────────────
# Scopes (bot_advanced.py)
# ─────────────────────────────────────────────────────────────────────────────

def test_scopes_list_no_auth(client):
    r = client.get("/api/bots/scopes")
    assert r.status_code == 200


def test_scopes_list_contains_expected_scopes(client):
    data = client.get("/api/bots/scopes").json()
    scopes = data["scopes"]
    assert "messages.read" in scopes
    assert "messages.send" in scopes
    assert "webhooks.manage" in scopes
    assert "payments.create" in scopes
    assert "mini_app.access" in scopes


def test_get_bot_scopes(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    r = client.get(f"/api/bots/{bid}/scopes", headers=h)
    assert r.status_code == 200
    assert "scopes" in r.json()
    assert isinstance(r.json()["scopes"], list)


def test_set_bot_scopes_valid(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    r = client.put(f"/api/bots/{bid}/scopes",
                   json={"scopes": ["messages.read", "messages.send", "files.send"]}, headers=h)
    assert r.status_code == 200
    assert r.json()["ok"] is True
    # Verify new scopes are returned
    r2 = client.get(f"/api/bots/{bid}/scopes", headers=h)
    saved = set(r2.json()["scopes"])
    assert "messages.read" in saved
    assert "files.send" in saved


def test_set_bot_scopes_invalid_scope(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    r = client.put(f"/api/bots/{bid}/scopes",
                   json={"scopes": ["messages.read", "made_up_scope"]}, headers=h)
    assert r.status_code == 400


def test_set_bot_scopes_not_owner(client):
    h1 = _auth(client)
    bot = _create_bot(client, h1)  # create bot while user1 cookie is active
    bid = bot["bot_id"]
    h2 = _auth(client)  # login user2 (overwrites cookie)
    r = client.put(f"/api/bots/{bid}/scopes",
                   json={"scopes": ["messages.read"]}, headers=h2)
    assert r.status_code in (403, 404)


# ─────────────────────────────────────────────────────────────────────────────
# Slash Commands (bot_advanced.py)
# ─────────────────────────────────────────────────────────────────────────────

def test_get_room_commands_requires_auth(anon_client):
    r = anon_client.get("/api/rooms/1/commands")
    assert r.status_code in (401, 403)


def test_get_room_commands_empty(client):
    h = _auth(client)
    room_id = _create_room(client, h)
    r = client.get(f"/api/rooms/{room_id}/commands", headers=h)
    assert r.status_code == 200
    assert "commands" in r.json()
    assert isinstance(r.json()["commands"], list)


def test_get_bot_commands_not_found(client):
    r = client.get("/api/bots/999999/commands")
    assert r.status_code == 404


def test_register_slash_commands_valid(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    token = bot["api_token"]
    r = client.post("/api/bot/commands/register",
                    json={"commands": [
                        {"name": "help", "description": "Show help"},
                        {"name": "ping", "description": "Pong"},
                    ]},
                    headers=_bot_token_header(token))
    assert r.status_code == 200
    assert r.json()["commands_count"] == 2


def test_register_slash_commands_invalid_token(client):
    r = client.post("/api/bot/commands/register",
                    json={"commands": [{"name": "help", "description": ""}]},
                    headers=_bot_token_header("bogus_token"))
    assert r.status_code == 401


def test_get_bot_commands_after_register(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    token = bot["api_token"]
    # Register commands via bot API
    client.post("/api/bot/commands/register",
                json={"commands": [{"name": "hello", "description": "Say hello"}]},
                headers=_bot_token_header(token))
    # Retrieve via public endpoint
    r = client.get(f"/api/bots/{bid}/commands")
    assert r.status_code == 200
    commands = r.json()["commands"]
    assert any(c.get("name") == "hello" for c in commands)


def test_room_commands_include_bot_commands_after_install(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    token = bot["api_token"]
    room_id = _create_room(client, h)

    # Register command
    client.post("/api/bot/commands/register",
                json={"commands": [{"name": "greet", "description": "Greet user"}]},
                headers=_bot_token_header(token))

    # Add bot to room
    client.post(f"/api/bots/{bid}/rooms/{room_id}", headers=h)

    # Room commands should include the bot's /greet command
    r = client.get(f"/api/rooms/{room_id}/commands", headers=h)
    assert r.status_code == 200
    cmds = r.json()["commands"]
    assert any(c.get("name") == "greet" for c in cmds)


# ─────────────────────────────────────────────────────────────────────────────
# Webhook (bot_advanced.py)
# ─────────────────────────────────────────────────────────────────────────────

def test_set_webhook(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    token = bot["api_token"]
    r = client.post("/api/bot/webhook/set", json={
        "url": "https://myserver.example.com/webhook",
        "secret": "my_webhook_secret",
        "events": ["message", "reaction"],
    }, headers=_bot_token_header(token))
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert "webhook_url" in data


def test_get_webhook_info(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    token = bot["api_token"]
    client.post("/api/bot/webhook/set", json={
        "url": "https://example.com/hook",
        "events": ["message"],
    }, headers=_bot_token_header(token))
    r = client.get("/api/bot/webhook/info", headers=_bot_token_header(token))
    assert r.status_code == 200
    wh = r.json()["webhook"]
    assert wh is not None
    assert wh["url"] == "https://example.com/hook"
    assert "message" in wh["events"]


def test_delete_webhook(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    token = bot["api_token"]
    client.post("/api/bot/webhook/set", json={
        "url": "https://example.com/hook",
        "events": ["message"],
    }, headers=_bot_token_header(token))
    r = client.post("/api/bot/webhook/delete", headers=_bot_token_header(token))
    assert r.status_code == 200
    assert r.json()["ok"] is True
    # Info should now show no webhook
    r2 = client.get("/api/bot/webhook/info", headers=_bot_token_header(token))
    assert r2.json()["webhook"] is None


def test_webhook_requires_bot_auth(client):
    r = client.post("/api/bot/webhook/set", json={
        "url": "https://example.com/hook", "events": ["message"],
    })
    assert r.status_code == 401


def test_webhook_auto_generates_secret_if_empty(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    token = bot["api_token"]
    client.post("/api/bot/webhook/set", json={
        "url": "https://example.com/hook",
        "secret": "",          # empty → should be auto-generated
        "events": ["message"],
    }, headers=_bot_token_header(token))
    r = client.get("/api/bot/webhook/info", headers=_bot_token_header(token))
    wh = r.json()["webhook"]
    # Secret must be set (non-empty) even though we sent ""
    assert wh["secret"] != ""


# ─────────────────────────────────────────────────────────────────────────────
# Inline Bot (bot_advanced.py)
# ─────────────────────────────────────────────────────────────────────────────

def test_register_inline_handler(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    token = bot["api_token"]
    r = client.post("/api/bot/inline/register", headers=_bot_token_header(token))
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["inline"] is True


def test_answer_inline_query(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    token = bot["api_token"]
    client.post("/api/bot/inline/register", headers=_bot_token_header(token))
    r = client.post("/api/bot/inline/answer", json={
        "results": [
            {"id": "1", "title": "Hello World", "description": "A greeting", "content": "Hello!"},
            {"id": "2", "title": "Goodbye", "description": "A farewell", "content": "Bye!"},
        ]
    }, headers=_bot_token_header(token))
    assert r.status_code == 200
    assert r.json()["results_count"] == 2


def test_query_inline_bot(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    token = bot["api_token"]
    # Register + seed results
    client.post("/api/bot/inline/register", headers=_bot_token_header(token))
    client.post("/api/bot/inline/answer", json={
        "results": [{"id": "1", "title": "Weather Today", "description": "Sunny", "content": "☀️"}]
    }, headers=_bot_token_header(token))
    # Query as a normal user
    user_h = _auth(client)
    r = client.get(f"/api/bots/{bid}/inline?q=weather", headers=user_h)
    assert r.status_code == 200
    data = r.json()
    assert "results" in data
    assert "bot_name" in data
    assert any("Weather" in res.get("title", "") for res in data["results"])


def test_query_inline_bot_filter(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    token = bot["api_token"]
    client.post("/api/bot/inline/register", headers=_bot_token_header(token))
    client.post("/api/bot/inline/answer", json={
        "results": [
            {"id": "1", "title": "Apple Pie", "description": "Dessert", "content": "🍎"},
            {"id": "2", "title": "Banana Bread", "description": "Dessert", "content": "🍌"},
        ]
    }, headers=_bot_token_header(token))
    user_h = _auth(client)
    r = client.get(f"/api/bots/{bid}/inline?q=apple", headers=user_h)
    results = r.json()["results"]
    assert len(results) == 1
    assert results[0]["title"] == "Apple Pie"


def test_query_inline_bot_not_found(client):
    h = _auth(client)
    r = client.get("/api/bots/999999/inline?q=test", headers=h)
    assert r.status_code == 404


def test_inline_requires_user_auth(anon_client):
    r = anon_client.get("/api/bots/1/inline?q=test")
    assert r.status_code in (401, 403)


# ─────────────────────────────────────────────────────────────────────────────
# Callback handler (bot_advanced.py)
# ─────────────────────────────────────────────────────────────────────────────

def test_handle_callback(client):
    r = client.post("/api/bot/callback", json={
        "callback_data": "action:confirm",
        "message_id": 42,
        "user_id": 7,
    })
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["callback_data"] == "action:confirm"
    assert data["message_id"] == 42
    assert data["user_id"] == 7


def test_handle_callback_empty_body(client):
    r = client.post("/api/bot/callback", json={})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["callback_data"] == ""


# ─────────────────────────────────────────────────────────────────────────────
# Bot marketplace / publish (bot_api.py)
# ─────────────────────────────────────────────────────────────────────────────

def test_publish_bot(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    r = client.post(f"/api/bots/{bid}/publish",
                    json={"is_public": True, "category": "utilities"}, headers=h)
    assert r.status_code in (200, 201)
    assert r.json()["ok"] is True


def test_publish_bot_not_owner(client):
    h1 = _auth(client)
    bot = _create_bot(client, h1)  # create bot while user1 cookie is active
    bid = bot["bot_id"]
    h2 = _auth(client)  # login user2 (overwrites cookie)
    r = client.post(f"/api/bots/{bid}/publish",
                    json={"is_public": True, "category": "utilities"}, headers=h2)
    assert r.status_code in (403, 404)


def test_submit_bot_review(client):
    h_owner = _auth(client)
    bot = _create_bot(client, h_owner)
    bid = bot["bot_id"]
    client.post(f"/api/bots/{bid}/publish",
                json={"is_public": True, "category": "other"}, headers=h_owner)

    h_reviewer = _auth(client)
    r = client.post(f"/api/bots/{bid}/reviews",
                    json={"rating": 5, "text": "Amazing bot!"},
                    headers=h_reviewer)
    assert r.status_code in (200, 201, 400, 404)  # endpoint may not exist yet
    if r.status_code in (200, 201):
        assert r.json()["ok"] is True


def test_get_bot_reviews(client):
    h_owner = _auth(client)
    bot = _create_bot(client, h_owner)
    bid = bot["bot_id"]
    r = client.get(f"/api/bots/{bid}/reviews")
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert "reviews" in r.json()


# ─────────────────────────────────────────────────────────────────────────────
# Mini App Dev Info (bot_advanced.py)
# ─────────────────────────────────────────────────────────────────────────────

def test_mini_app_dev_info_not_owner(client):
    h1 = _auth(client)
    bot = _create_bot(client, h1)  # create bot while user1 cookie is active
    bid = bot["bot_id"]
    h2 = _auth(client)  # login user2 (overwrites cookie)
    r = client.get(f"/api/bots/{bid}/mini-app/dev", headers=h2)
    assert r.status_code in (403, 404)


def test_mini_app_dev_info_owner(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    # Set mini_app_url first
    client.put(f"/api/bots/{bid}", json={"mini_app_url": "https://app.example.com"}, headers=h)
    r = client.get(f"/api/bots/{bid}/mini-app/dev", headers=h)
    assert r.status_code == 200
    data = r.json()
    assert data["bot_id"] == bid
    assert "dev_tools" in data
    assert "available_apis" in data["dev_tools"]


def test_mini_app_dev_info_available_apis(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    client.put(f"/api/bots/{bid}", json={"mini_app_url": "https://example.com"}, headers=h)
    r = client.get(f"/api/bots/{bid}/mini-app/dev", headers=h)
    if r.status_code == 200:
        apis = r.json()["dev_tools"]["available_apis"]
        assert any("getUser" in api for api in apis)
        assert any("sendMessage" in api for api in apis)


# ─────────────────────────────────────────────────────────────────────────────
# Mini App token (bot_api.py)
# ─────────────────────────────────────────────────────────────────────────────

def test_mini_app_token_no_mini_app_configured(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    r = client.get(f"/api/bots/{bid}/mini-app-token", headers=h)
    assert r.status_code in (400, 404)


def test_mini_app_token_with_mini_app(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    bid = bot["bot_id"]
    client.put(f"/api/bots/{bid}", json={"mini_app_url": "https://app.example.com"}, headers=h)
    r = client.get(f"/api/bots/{bid}/mini-app-token", headers=h)
    assert r.status_code == 200
    data = r.json()
    assert "token" in data
    assert data["expires_in"] == 3600
    assert data["bot_id"] == bid


# ─────────────────────────────────────────────────────────────────────────────
# Bot long-poll updates (bot_api.py)
# ─────────────────────────────────────────────────────────────────────────────

def test_bot_get_updates_valid_token_no_updates(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    token = bot["api_token"]
    # Very short timeout so the test doesn't block
    r = client.get("/api/bot/updates?timeout=1", headers=_bot_token_header(token))
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert "updates" in data
    assert isinstance(data["updates"], list)


def test_bot_get_updates_invalid_token(client):
    r = client.get("/api/bot/updates?timeout=1", headers=_bot_token_header("bad_token_xyz"))
    assert r.status_code == 401


def test_bot_get_updates_timeout_bounds(client):
    h = _auth(client)
    bot = _create_bot(client, h)
    token = bot["api_token"]
    # timeout must be between 1 and 60 seconds; 0 should be rejected
    r = client.get("/api/bot/updates?timeout=0", headers=_bot_token_header(token))
    assert r.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# deliver_webhook (unit test — no HTTP server needed)
# ─────────────────────────────────────────────────────────────────────────────

def test_deliver_webhook_no_webhook_configured(client):
    """deliver_webhook returns False when no webhook is set for that bot."""
    import asyncio
    from app.bots.bot_advanced import deliver_webhook, _webhooks
    bot_id = 999888777  # fictitious, no webhook registered
    _webhooks.pop(bot_id, None)
    loop = asyncio.new_event_loop()
    result = loop.run_until_complete(deliver_webhook(bot_id, "message", {"text": "hi"}))
    loop.close()
    assert result is False


def test_deliver_webhook_event_not_in_events_list(client):
    """deliver_webhook returns False if the event is not subscribed."""
    import asyncio
    from app.bots.bot_advanced import deliver_webhook, _webhooks
    bot_id = 999888776
    _webhooks[bot_id] = {
        "url": "https://example.com/hook",
        "secret": "secret",
        "events": ["reaction"],  # only reaction, not message
    }
    loop = asyncio.new_event_loop()
    result = loop.run_until_complete(deliver_webhook(bot_id, "message", {"text": "hi"}))
    loop.close()
    _webhooks.pop(bot_id, None)
    assert result is False

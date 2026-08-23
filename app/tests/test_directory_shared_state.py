"""Справочники, переехавшие из памяти процесса в базу (срез 7 миграции).

Черновики, вебхуки ботов, их права и inline-ответы, карта распределённого файла
и подписки UnifiedPush жили в словарях модуля: воркер, принявший запись, был
единственным, кто её видел, а остальные отвечали «нет такого». Здесь
проверяется то, что делает эти роуты пригодными для нескольких воркеров: запись
одного запроса видна из отдельной сессии базы, то есть переживает процесс,
который её принял.
"""

import json
import secrets
from datetime import datetime, timedelta, timezone

import pytest

from app.bots import bot_advanced
from app.chats.messages import moderation
from app.database import SessionLocal
from app.models import BotInlineResults, BotScope, BotWebhook, DistributedChunk, DistributedFile, User
from app.models import UnifiedPushSubscription as UnifiedPush
from app.models_rooms import MessageDraft


@pytest.fixture
def another_worker():
    """Сессия базы в стороне от запроса — то, что увидел бы соседний воркер."""
    session = SessionLocal()
    yield session
    session.close()


def account_id(session, logged_user: dict) -> int:
    return session.query(User).filter(User.username == logged_user["username"]).one().id


def make_room(client, logged_user: dict) -> int:
    r = client.post(
        "/api/rooms",
        json={
            "name": f"dir_{secrets.token_hex(4)}",
            "is_public": True,
            "encrypted_room_key": {
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(60),
            },
        },
        headers=logged_user["headers"],
    )
    assert r.status_code in (200, 201), r.text
    body = r.json()
    return body.get("id") or body["room"]["id"]


@pytest.fixture
def room(client, logged_user):
    return make_room(client, logged_user)


@pytest.fixture
def bot(client, logged_user):
    r = client.post(
        "/api/bots",
        json={"name": f"DirBot_{secrets.token_hex(3)}", "description": "срез 7"},
        headers=logged_user["headers"],
    )
    assert r.status_code == 201, r.text
    return r.json()


def bot_header(bot: dict) -> dict:
    return {"Authorization": f"Bot {bot['api_token']}"}


class TestDrafts:
    def test_a_saved_draft_is_visible_outside_the_process_that_took_it(
        self, client, logged_user, room, another_worker
    ):
        r = client.post(
            f"/api/rooms/{room}/draft",
            json={"text": "недописанное"},
            headers=logged_user["headers"],
        )
        assert r.status_code == 200, r.text

        stored = another_worker.query(MessageDraft).filter(MessageDraft.room_id == room).one()
        assert stored.text == "недописанное"

    def test_saving_twice_replaces_the_text_instead_of_adding_a_second_draft(
        self, client, logged_user, room, another_worker
    ):
        for text in ("первый", "второй"):
            client.post(f"/api/rooms/{room}/draft", json={"text": text}, headers=logged_user["headers"])

        stored = another_worker.query(MessageDraft).filter(MessageDraft.room_id == room).all()
        assert [draft.text for draft in stored] == ["второй"]
        assert client.get(f"/api/rooms/{room}/draft", headers=logged_user["headers"]).json()["text"] == "второй"

    def test_a_room_without_a_draft_answers_with_an_empty_one(self, client, logged_user, room):
        r = client.get(f"/api/rooms/{room}/draft", headers=logged_user["headers"])
        assert r.status_code == 200
        assert r.json() == {"room_id": room, "text": ""}

    def test_a_cleared_draft_disappears_from_the_table(self, client, logged_user, room, another_worker):
        client.post(f"/api/rooms/{room}/draft", json={"text": "стереть"}, headers=logged_user["headers"])
        assert client.delete(f"/api/rooms/{room}/draft", headers=logged_user["headers"]).status_code == 200

        assert another_worker.query(MessageDraft).filter(MessageDraft.room_id == room).count() == 0

    def test_a_draft_untouched_past_the_lifetime_is_forgotten_and_a_fresh_one_is_not(
        self, client, logged_user, room, another_worker
    ):
        client.post(f"/api/rooms/{room}/draft", json={"text": "свежий"}, headers=logged_user["headers"])
        forgotten_room = make_room(client, logged_user)
        client.post(
            f"/api/rooms/{forgotten_room}/draft",
            json={"text": "старый"},
            headers=logged_user["headers"],
        )
        stale = (
            another_worker.query(MessageDraft).filter(MessageDraft.room_id == forgotten_room).one()
        )
        stale.updated_at = datetime.now(timezone.utc) - timedelta(days=moderation.DRAFT_LIFETIME_DAYS + 1)
        another_worker.commit()
        stale_id = stale.id

        moderation.forget_stale_drafts(another_worker)

        assert another_worker.query(MessageDraft).filter(MessageDraft.id == stale_id).count() == 0
        assert another_worker.query(MessageDraft).filter(MessageDraft.room_id == room).count() == 1


class TestBotWebhooks:
    def test_a_webhook_set_by_one_request_is_visible_outside_it(self, client, bot, another_worker):
        r = client.post(
            "/api/bot/webhook/set",
            json={"url": "https://hooks.test/vortex", "secret": "s" * 16, "events": ["message"]},
            headers=bot_header(bot),
        )
        assert r.status_code == 200, r.text

        stored = another_worker.query(BotWebhook).filter(BotWebhook.bot_id == bot["bot_id"]).one()
        assert stored.url == "https://hooks.test/vortex"
        assert json.loads(stored.events) == ["message"]

    def test_setting_a_webhook_twice_keeps_a_single_row(self, client, bot, another_worker):
        for url in ("https://first.test/hook", "https://second.test/hook"):
            client.post(
                "/api/bot/webhook/set",
                json={"url": url, "events": ["message"]},
                headers=bot_header(bot),
            )

        stored = another_worker.query(BotWebhook).filter(BotWebhook.bot_id == bot["bot_id"]).all()
        assert [row.url for row in stored] == ["https://second.test/hook"]

    def test_the_info_route_reads_back_what_was_stored(self, client, bot):
        client.post(
            "/api/bot/webhook/set",
            json={"url": "https://hooks.test/read", "secret": "d" * 12, "events": ["reaction"]},
            headers=bot_header(bot),
        )
        body = client.get("/api/bot/webhook/info", headers=bot_header(bot)).json()["webhook"]
        assert body["url"] == "https://hooks.test/read"
        assert body["secret"] == "d" * 12
        assert body["events"] == ["reaction"]

    def test_a_bot_without_a_webhook_answers_with_none(self, client, bot):
        assert client.get("/api/bot/webhook/info", headers=bot_header(bot)).json()["webhook"] is None

    def test_a_deleted_webhook_disappears_from_the_table(self, client, bot, another_worker):
        client.post(
            "/api/bot/webhook/set",
            json={"url": "https://hooks.test/gone", "events": []},
            headers=bot_header(bot),
        )
        assert client.post("/api/bot/webhook/delete", headers=bot_header(bot)).status_code == 200

        assert another_worker.query(BotWebhook).filter(BotWebhook.bot_id == bot["bot_id"]).count() == 0

    def test_delivery_refuses_an_event_the_stored_webhook_never_subscribed_to(self, client, bot):
        import asyncio

        client.post(
            "/api/bot/webhook/set",
            json={"url": "https://hooks.test/reaction", "events": ["reaction"]},
            headers=bot_header(bot),
        )
        loop = asyncio.new_event_loop()
        delivered = loop.run_until_complete(bot_advanced.deliver_webhook(bot["bot_id"], "message", {}))
        loop.close()
        assert delivered is False


class TestBotScopes:
    def test_granted_scopes_are_visible_outside_the_request_that_set_them(
        self, client, logged_user, bot, another_worker
    ):
        r = client.put(
            f"/api/bots/{bot['bot_id']}/scopes",
            json={"scopes": ["messages.read", "profile.read"]},
            headers=logged_user["headers"],
        )
        assert r.status_code == 200, r.text

        stored = another_worker.query(BotScope).filter(BotScope.bot_id == bot["bot_id"]).all()
        assert sorted(row.scope for row in stored) == ["messages.read", "profile.read"]

    def test_setting_scopes_again_replaces_them(self, client, logged_user, bot, another_worker):
        for scopes in (["messages.read", "messages.send"], ["profile.read"]):
            client.put(
                f"/api/bots/{bot['bot_id']}/scopes",
                json={"scopes": scopes},
                headers=logged_user["headers"],
            )

        stored = another_worker.query(BotScope).filter(BotScope.bot_id == bot["bot_id"]).all()
        assert [row.scope for row in stored] == ["profile.read"]

    def test_a_bot_nobody_granted_anything_answers_with_the_default_pair(self, client, logged_user, bot):
        body = client.get(f"/api/bots/{bot['bot_id']}/scopes", headers=logged_user["headers"]).json()
        assert sorted(body["scopes"]) == sorted(bot_advanced.DEFAULT_SCOPES)

    def test_the_route_reads_back_the_stored_grant(self, client, logged_user, bot):
        client.put(
            f"/api/bots/{bot['bot_id']}/scopes",
            json={"scopes": ["payments.create"]},
            headers=logged_user["headers"],
        )
        body = client.get(f"/api/bots/{bot['bot_id']}/scopes", headers=logged_user["headers"]).json()
        assert body["scopes"] == ["payments.create"]


class TestInlineAnswers:
    def test_an_answer_is_visible_outside_the_request_that_stored_it(self, client, bot, another_worker):
        r = client.post(
            "/api/bot/inline/answer",
            json={"results": [{"id": "1", "title": "Привет", "content": "мир"}]},
            headers=bot_header(bot),
        )
        assert r.status_code == 200, r.text

        stored = another_worker.query(BotInlineResults).filter(BotInlineResults.bot_id == bot["bot_id"]).one()
        assert json.loads(stored.results)[0]["title"] == "Привет"

    def test_the_query_route_reads_back_the_stored_answer(self, client, logged_user, bot):
        client.post(
            "/api/bot/inline/answer",
            json={"results": [{"id": "1", "title": "Погода", "content": "дождь"}]},
            headers=bot_header(bot),
        )
        body = client.get(f"/api/bots/{bot['bot_id']}/inline", headers=logged_user["headers"]).json()
        assert [result["title"] for result in body["results"]] == ["Погода"]

    def test_a_query_filters_the_stored_answer_by_its_text(self, client, logged_user, bot):
        client.post(
            "/api/bot/inline/answer",
            json={
                "results": [
                    {"id": "1", "title": "Погода", "content": "дождь"},
                    {"id": "2", "title": "Курс", "content": "рубль"},
                ]
            },
            headers=bot_header(bot),
        )
        body = client.get(
            f"/api/bots/{bot['bot_id']}/inline",
            params={"q": "курс"},
            headers=logged_user["headers"],
        ).json()
        assert [result["title"] for result in body["results"]] == ["Курс"]

    def test_registering_an_inline_bot_leaves_an_empty_answer_behind(self, client, bot, another_worker):
        assert client.post("/api/bot/inline/register", headers=bot_header(bot)).status_code == 200

        stored = another_worker.query(BotInlineResults).filter(BotInlineResults.bot_id == bot["bot_id"]).one()
        assert json.loads(stored.results) == []

    def test_beyond_the_ceiling_the_oldest_answer_is_dropped(
        self, client, logged_user, bot, another_worker, monkeypatch
    ):
        earlier = client.post(
            "/api/bots",
            json={"name": f"OldBot_{secrets.token_hex(3)}", "description": "срез 7"},
            headers=logged_user["headers"],
        ).json()
        client.post("/api/bot/inline/answer", json={"results": []}, headers=bot_header(earlier))
        older = (
            another_worker.query(BotInlineResults)
            .filter(BotInlineResults.bot_id == earlier["bot_id"])
            .one()
        )
        older.updated_at = datetime.now(timezone.utc) - timedelta(days=1)
        another_worker.commit()
        older_id = older.id

        monkeypatch.setattr(bot_advanced, "_MAX_INLINE_BOTS", 1)
        client.post("/api/bot/inline/answer", json={"results": []}, headers=bot_header(bot))

        another_worker.expire_all()
        assert another_worker.query(BotInlineResults).filter(BotInlineResults.id == older_id).count() == 0
        assert (
            another_worker.query(BotInlineResults).filter(BotInlineResults.bot_id == bot["bot_id"]).count() == 1
        )


class TestDistributedFiles:
    def payload(self) -> dict:
        return {
            "file_hash": secrets.token_hex(16),
            "filename": "notes.txt",
            "total_size": 2048,
            "chunk_count": 2,
            "chunks": [
                {
                    "chunk_hash": secrets.token_hex(16),
                    "chunk_index": index,
                    "size": 1024,
                    "node_ip": "10.0.0.1",
                    "node_port": 9000 + index,
                }
                for index in range(2)
            ],
        }

    def test_a_registered_file_is_visible_outside_the_request_that_stored_it(
        self, client, logged_user, another_worker
    ):
        body = self.payload()
        r = client.post("/api/files/distributed/register", json=body, headers=logged_user["headers"])
        assert r.status_code == 200, r.text

        stored = (
            another_worker.query(DistributedFile).filter(DistributedFile.file_hash == body["file_hash"]).one()
        )
        chunks = another_worker.query(DistributedChunk).filter(DistributedChunk.file_id == stored.id).all()
        assert stored.filename == "notes.txt"
        assert sorted(chunk.node_port for chunk in chunks) == [9000, 9001]

    def test_registering_the_same_file_again_replaces_its_chunks(self, client, logged_user, another_worker):
        body = self.payload()
        client.post("/api/files/distributed/register", json=body, headers=logged_user["headers"])
        body["chunks"] = body["chunks"][:1]
        body["chunk_count"] = 1
        client.post("/api/files/distributed/register", json=body, headers=logged_user["headers"])

        stored = (
            another_worker.query(DistributedFile).filter(DistributedFile.file_hash == body["file_hash"]).one()
        )
        chunks = another_worker.query(DistributedChunk).filter(DistributedChunk.file_id == stored.id).all()
        assert len(chunks) == 1

    def test_the_map_route_reads_back_the_stored_chunks(self, client, logged_user):
        body = self.payload()
        client.post("/api/files/distributed/register", json=body, headers=logged_user["headers"])

        found = client.get(f"/api/files/distributed/{body['file_hash']}", headers=logged_user["headers"]).json()
        assert found["filename"] == "notes.txt"
        assert [chunk["chunk_index"] for chunk in found["chunks"]] == [0, 1]

    def test_a_file_nobody_registered_answers_404(self, client, logged_user):
        r = client.get(f"/api/files/distributed/{secrets.token_hex(16)}", headers=logged_user["headers"])
        assert r.status_code == 404

    def test_the_listing_shows_the_stored_file(self, client, logged_user):
        body = self.payload()
        client.post("/api/files/distributed/register", json=body, headers=logged_user["headers"])

        listed = client.get("/api/files/distributed/list", headers=logged_user["headers"]).json()["files"]
        assert body["file_hash"] in {entry["file_hash"] for entry in listed}


class TestUnifiedPushSubscriptions:
    def endpoint(self) -> str:
        return f"https://ntfy.test/{secrets.token_hex(8)}"

    def test_a_registered_endpoint_is_visible_outside_the_request_that_stored_it(
        self, client, logged_user, another_worker
    ):
        endpoint = self.endpoint()
        r = client.post(
            "/api/native/push/register",
            json={"token": endpoint, "platform": "unified_push"},
            headers=logged_user["headers"],
        )
        assert r.status_code == 200, r.text

        stored = another_worker.query(UnifiedPush).filter(UnifiedPush.endpoint == endpoint).one()
        assert stored.user_id == account_id(another_worker, logged_user)
        assert stored.active is True

    def test_registering_one_endpoint_twice_keeps_a_single_row(self, client, logged_user, another_worker):
        endpoint = self.endpoint()
        for _ in range(2):
            client.post(
                "/api/native/push/register",
                json={"token": endpoint, "platform": "unified_push"},
                headers=logged_user["headers"],
            )

        assert another_worker.query(UnifiedPush).filter(UnifiedPush.endpoint == endpoint).count() == 1

    def test_the_listing_route_reads_back_the_stored_endpoint(self, client, logged_user):
        endpoint = self.endpoint()
        client.post(
            "/api/native/push/register",
            json={"token": endpoint, "platform": "unified_push"},
            headers=logged_user["headers"],
        )

        listed = client.get("/api/native/push/subscriptions", headers=logged_user["headers"]).json()
        assert any(row["endpoint"].startswith(endpoint[:60]) for row in listed["subscriptions"])

    def test_an_unregistered_endpoint_disappears_from_the_table(self, client, logged_user, another_worker):
        endpoint = self.endpoint()
        client.post(
            "/api/native/push/register",
            json={"token": endpoint, "platform": "unified_push"},
            headers=logged_user["headers"],
        )
        r = client.post(
            "/api/native/push/unregister",
            json={"endpoint": endpoint},
            headers=logged_user["headers"],
        )
        assert r.json() == {"ok": True, "removed": True}

        assert another_worker.query(UnifiedPush).filter(UnifiedPush.endpoint == endpoint).count() == 0

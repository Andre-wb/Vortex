"""Round-trip Python ↔ Rust по одной и той же базе Postgres (Фаза 3).

Гейт — переменная окружения `VORTEX_TEST_PG_URL`: без неё тесты пропускаются,
потому что весь остальной прогон идёт на SQLite, а `vortex-storage` собран
только под Postgres. Схема в целевой базе разворачивается из тех же моделей
SQLAlchemy (`scripts/pg_schema_for_sqlx.py` делает то же самое).

Отметки времени пишутся наивными намеренно: колонки объявлены как
`timestamp without time zone`, и psycopg2 приводит осведомлённое время к
часовому поясу сессии. Здесь проверяется, что Rust отдаёт ровно ту же
настенную отметку, что записал Python, без собственной трактовки пояса.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.base import Base
from app.models.bot import Bot, BotInlineResults, BotScope, BotWebhook
from app.models.media import DistributedChunk, DistributedFile, UnifiedPushSubscription
from app.models.prekeys import OneTimeKyberPreKey, OneTimePreKey, PreKeyBundle
from app.models.user import User, UserDevice
from app.models_rooms.messages import MessageDraft
from app.models_rooms.rooms import Room

vortex_chat = pytest.importorskip("vortex_chat", reason="Rust-расширение не собрано")

PG_URL = os.environ.get("VORTEX_TEST_PG_URL", "")

pytestmark = pytest.mark.skipif(
    not PG_URL,
    reason="VORTEX_TEST_PG_URL не задан — round-trip с Postgres пропущен",
)

WRITTEN_AT = datetime(2026, 8, 17, 9, 15, 30, 715103)
WRITTEN_UNIX = (1_786_958_130, 715_103)


def _sqlalchemy_url(url: str) -> str:
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql://", 1)
    return url


SCHEMA_LOCK_KEY = 0x564F5254


@pytest.fixture(scope="module")
def pg_sessions():
    engine = create_engine(_sqlalchemy_url(PG_URL), future=True)
    with engine.begin() as conn:
        conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": SCHEMA_LOCK_KEY})
        Base.metadata.create_all(bind=conn)
    maker = sessionmaker(bind=engine, autoflush=False, future=True)
    assert vortex_chat.storage_connect_postgres(PG_URL, 4) is True
    assert vortex_chat.storage_is_connected() is True
    yield maker
    engine.dispose()


@pytest.fixture
def account(pg_sessions):
    session = pg_sessions()
    user = User(username=f"rt-{uuid.uuid4().hex[:16]}", password_hash="x")
    session.add(user)
    session.commit()
    client_device_id = uuid.uuid4().hex
    device = UserDevice(user_id=user.id, device_name="round-trip", client_device_id=client_device_id)
    session.add(device)
    session.commit()
    yield session, user.id, device.id, client_device_id
    session.query(User).filter(User.id == user.id).delete()
    session.commit()
    session.close()


def _fields(bundle) -> dict:
    return {
        "device_id": bundle.device_id,
        "identity_key": bundle.identity_key,
        "signed_prekey": bundle.signed_prekey,
        "signed_prekey_sig": bundle.signed_prekey_sig,
        "signed_prekey_id": bundle.signed_prekey_id,
        "identity_key_ed": bundle.identity_key_ed,
        "identity_key_sig": bundle.identity_key_sig,
        "supports_v2": bundle.supports_v2,
        "device_x3dh_pub": bundle.device_x3dh_pub,
        "device_sign_pub": bundle.device_sign_pub,
        "device_cert_sig": bundle.device_cert_sig,
        "client_device_id": bundle.client_device_id,
        "device_kyber_pub": bundle.device_kyber_pub,
        "device_kyber_sig": bundle.device_kyber_sig,
        "device_kyber_id": bundle.device_kyber_id,
    }


def _sample_values(device_id: int | None, client_device_id: str, spk_id: int) -> dict:
    return {
        "device_id": device_id,
        "identity_key": bytes([0x11]) * 32,
        "signed_prekey": bytes([0x22]) * 32,
        "signed_prekey_sig": bytes([0x33]) * 64,
        "signed_prekey_id": spk_id,
        "identity_key_ed": bytes([0x44]) * 32,
        "identity_key_sig": bytes([0x55]) * 64,
        "supports_v2": True,
        "device_x3dh_pub": bytes([0x66]) * 32,
        "device_sign_pub": bytes([0x77]) * 32,
        "device_cert_sig": bytes([0x88]) * 64,
        "client_device_id": client_device_id,
        "device_kyber_pub": bytes([0x99]) * 1184,
        "device_kyber_sig": bytes([0xAA]) * 64,
        "device_kyber_id": 3,
    }


def test_rust_reads_the_bundle_python_wrote(account):
    session, user_id, device_id, client_device_id = account
    values = _sample_values(device_id, client_device_id, 11)
    session.add(PreKeyBundle(user_id=user_id, created_at=WRITTEN_AT, updated_at=WRITTEN_AT, **values))
    session.commit()

    record = vortex_chat.storage_bundle_of_device(user_id, device_id)
    assert record is not None
    assert _fields(record.bundle) == values
    assert record.created_at == WRITTEN_UNIX
    assert record.updated_at == WRITTEN_UNIX
    assert record.user_id == user_id


def test_python_reads_the_bundle_rust_wrote(account):
    session, user_id, device_id, client_device_id = account
    values = _sample_values(device_id, client_device_id, 22)
    written = vortex_chat.StoredPreKeyBundle(
        values["identity_key"],
        values["signed_prekey"],
        values["signed_prekey_sig"],
        values["signed_prekey_id"],
        device_id=values["device_id"],
        identity_key_ed=values["identity_key_ed"],
        identity_key_sig=values["identity_key_sig"],
        supports_v2=values["supports_v2"],
        device_x3dh_pub=values["device_x3dh_pub"],
        device_sign_pub=values["device_sign_pub"],
        device_cert_sig=values["device_cert_sig"],
        client_device_id=values["client_device_id"],
        device_kyber_pub=values["device_kyber_pub"],
        device_kyber_sig=values["device_kyber_sig"],
        device_kyber_id=values["device_kyber_id"],
    )
    row_id, created = vortex_chat.storage_save_bundle(user_id, written, *WRITTEN_UNIX)
    assert created is True

    stored = session.get(PreKeyBundle, row_id)
    session.refresh(stored)
    assert _fields(stored) == values
    assert stored.created_at == WRITTEN_AT
    assert stored.updated_at == WRITTEN_AT


def test_rust_updates_the_bundle_python_published(account):
    session, user_id, device_id, client_device_id = account
    values = _sample_values(device_id, client_device_id, 1)
    session.add(PreKeyBundle(user_id=user_id, created_at=WRITTEN_AT, updated_at=WRITTEN_AT, **values))
    session.commit()

    later = _sample_values(device_id, client_device_id, 2)
    written = vortex_chat.StoredPreKeyBundle(
        later["identity_key"],
        later["signed_prekey"],
        later["signed_prekey_sig"],
        later["signed_prekey_id"],
        device_id=later["device_id"],
        client_device_id=later["client_device_id"],
    )
    row_id, created = vortex_chat.storage_save_bundle(user_id, written, WRITTEN_UNIX[0] + 60, 0)
    assert created is False

    session.expire_all()
    stored = session.get(PreKeyBundle, row_id)
    assert stored.signed_prekey_id == 2
    assert stored.identity_key_ed is None
    assert stored.created_at == WRITTEN_AT
    assert stored.updated_at == datetime(2026, 8, 17, 9, 16, 30)
    assert session.query(PreKeyBundle).filter(PreKeyBundle.user_id == user_id).count() == 1


@pytest.mark.parametrize(
    ("kyber", "model", "width"),
    [(False, OneTimePreKey, 32), (True, OneTimeKyberPreKey, 1184)],
)
def test_one_time_keys_cross_the_boundary_in_both_directions(account, kyber, model, width):
    session, user_id, device_id, _ = account

    session.add(
        model(
            user_id=user_id,
            device_id=device_id,
            key_id=1,
            public_key=bytes([0x01]) * width,
            used=False,
            created_at=WRITTEN_AT,
        )
    )
    session.commit()
    assert vortex_chat.storage_available_one_time_keys(user_id, device_id, kyber) == 1

    added = vortex_chat.storage_add_one_time_keys(
        user_id,
        device_id,
        [(2, bytes([0x02]) * width), (3, bytes([0x03]) * width)],
        *WRITTEN_UNIX,
        kyber,
    )
    assert added == 2
    session.expire_all()
    rows = (
        session.query(model)
        .filter(model.user_id == user_id, model.device_id == device_id)
        .order_by(model.key_id)
        .all()
    )
    assert [(row.key_id, row.public_key, row.used) for row in rows] == [
        (1, bytes([0x01]) * width, False),
        (2, bytes([0x02]) * width, False),
        (3, bytes([0x03]) * width, False),
    ]
    assert rows[1].created_at == WRITTEN_AT

    taken = vortex_chat.storage_take_one_time_key(user_id, device_id, kyber)
    assert taken == (1, bytes([0x01]) * width)
    session.expire_all()
    assert session.get(model, rows[0].id).used is True
    assert vortex_chat.storage_available_one_time_keys(user_id, device_id, kyber) == 2


def test_rust_resolves_the_device_python_registered(account):
    _session, user_id, device_id, client_device_id = account
    assert vortex_chat.storage_device_of(user_id, client_device_id) == device_id
    assert vortex_chat.storage_device_of(user_id, uuid.uuid4().hex) is None


@pytest.fixture
def bot_account(pg_sessions):
    session = pg_sessions()
    owner = User(username=f"rt-owner-{uuid.uuid4().hex[:12]}", password_hash="x")
    account = User(username=f"rt-bot-{uuid.uuid4().hex[:12]}", password_hash="x", is_bot=True)
    session.add_all([owner, account])
    session.commit()
    bot = Bot(user_id=account.id, owner_id=owner.id, api_token=uuid.uuid4().hex, name="round-trip")
    session.add(bot)
    session.commit()
    yield session, bot.id
    session.query(User).filter(User.id.in_([owner.id, account.id])).delete(synchronize_session=False)
    session.commit()
    session.close()


@pytest.fixture
def member_room(pg_sessions):
    session = pg_sessions()
    user = User(username=f"rt-draft-{uuid.uuid4().hex[:12]}", password_hash="x")
    session.add(user)
    session.commit()
    room = Room(name="round-trip", invite_code=uuid.uuid4().hex[:16], creator_id=user.id)
    session.add(room)
    session.commit()
    yield session, user.id, room.id
    session.query(Room).filter(Room.id == room.id).delete()
    session.query(User).filter(User.id == user.id).delete()
    session.commit()
    session.close()


def test_rust_reads_the_webhook_python_stored(bot_account):
    session, bot_id = bot_account
    session.add(
        BotWebhook(
            bot_id=bot_id,
            url="https://hooks.test/python",
            secret="p" * 16,
            events=json.dumps(["message"]),
            created_at=WRITTEN_AT,
        )
    )
    session.commit()

    assert vortex_chat.storage_webhook_of(bot_id) == (
        "https://hooks.test/python",
        "p" * 16,
        json.dumps(["message"]),
        *WRITTEN_UNIX,
    )


def test_python_reads_the_webhook_rust_stored(bot_account):
    session, bot_id = bot_account
    vortex_chat.storage_save_webhook(
        bot_id, "https://hooks.test/rust", "r" * 16, json.dumps(["reaction"]), *WRITTEN_UNIX
    )

    session.expire_all()
    stored = session.query(BotWebhook).filter(BotWebhook.bot_id == bot_id).one()
    assert (stored.url, stored.secret, json.loads(stored.events)) == (
        "https://hooks.test/rust",
        "r" * 16,
        ["reaction"],
    )
    assert stored.created_at == WRITTEN_AT

    assert vortex_chat.storage_forget_webhook(bot_id) is True
    session.expire_all()
    assert session.query(BotWebhook).filter(BotWebhook.bot_id == bot_id).count() == 0


def test_both_runtimes_see_one_set_of_granted_scopes(bot_account):
    session, bot_id = bot_account
    session.add_all([BotScope(bot_id=bot_id, scope="messages.read"), BotScope(bot_id=bot_id, scope="profile.read")])
    session.commit()

    assert vortex_chat.storage_bot_scopes(bot_id) == ["messages.read", "profile.read"]

    vortex_chat.storage_replace_bot_scopes(bot_id, ["payments.create"])
    session.expire_all()
    stored = session.query(BotScope).filter(BotScope.bot_id == bot_id).all()
    assert [row.scope for row in stored] == ["payments.create"]


def test_both_runtimes_see_one_inline_answer(bot_account):
    session, bot_id = bot_account
    answer = json.dumps([{"id": "1", "title": "Привет"}], ensure_ascii=False)
    session.add(BotInlineResults(bot_id=bot_id, results=answer, updated_at=WRITTEN_AT))
    session.commit()

    assert vortex_chat.storage_inline_results(bot_id) == answer

    vortex_chat.storage_remember_inline(bot_id, "[]", WRITTEN_UNIX[0] + 60, 0)
    session.expire_all()
    stored = session.query(BotInlineResults).filter(BotInlineResults.bot_id == bot_id).one()
    assert stored.results == "[]"
    assert stored.updated_at == datetime(2026, 8, 17, 9, 16, 30)


def test_both_runtimes_see_one_draft(member_room):
    session, user_id, room_id = member_room
    session.add(MessageDraft(user_id=user_id, room_id=room_id, text="из питона", updated_at=WRITTEN_AT))
    session.commit()

    assert vortex_chat.storage_draft_of(user_id, room_id) == ("из питона", *WRITTEN_UNIX)

    vortex_chat.storage_save_draft(user_id, room_id, "из раста", *WRITTEN_UNIX)
    session.expire_all()
    stored = session.query(MessageDraft).filter(MessageDraft.room_id == room_id).one()
    assert stored.text == "из раста"
    assert stored.updated_at == WRITTEN_AT

    assert vortex_chat.storage_clear_draft(user_id, room_id) is True
    session.expire_all()
    assert session.query(MessageDraft).filter(MessageDraft.room_id == room_id).count() == 0


def test_rust_forgets_the_stale_draft_python_left(member_room):
    session, user_id, room_id = member_room
    session.add(MessageDraft(user_id=user_id, room_id=room_id, text="забытое", updated_at=WRITTEN_AT))
    session.commit()

    removed = vortex_chat.storage_forget_stale_drafts(WRITTEN_UNIX[0] + 1, 0)
    assert removed >= 1
    session.expire_all()
    assert session.query(MessageDraft).filter(MessageDraft.room_id == room_id).count() == 0


def test_both_runtimes_see_one_distributed_file(account):
    session, user_id, _device_id, _client_device_id = account
    file_hash = uuid.uuid4().hex
    chunk_hash = uuid.uuid4().hex
    stored = DistributedFile(
        file_hash=file_hash,
        filename="notes.txt",
        total_size=2048,
        chunk_count=1,
        uploader_id=user_id,
        created_at=WRITTEN_AT,
    )
    session.add(stored)
    session.commit()
    session.add(
        DistributedChunk(
            file_id=stored.id,
            chunk_hash=chunk_hash,
            chunk_index=0,
            size=1024,
            node_ip="10.0.0.1",
            node_port=9000,
        )
    )
    session.commit()

    assert vortex_chat.storage_locate_distributed(file_hash) == (
        "notes.txt",
        2048,
        1,
        user_id,
        *WRITTEN_UNIX,
        [(chunk_hash, 0, 1024, "10.0.0.1", 9000)],
    )

    written_hash = uuid.uuid4().hex
    vortex_chat.storage_register_distributed(
        written_hash,
        "rust.txt",
        1024,
        1,
        user_id,
        *WRITTEN_UNIX,
        [(chunk_hash, 0, 1024, "10.0.0.2", 9001)],
    )
    session.expire_all()
    written = session.query(DistributedFile).filter(DistributedFile.file_hash == written_hash).one()
    chunks = session.query(DistributedChunk).filter(DistributedChunk.file_id == written.id).all()
    assert written.filename == "rust.txt"
    assert [(chunk.node_ip, chunk.node_port) for chunk in chunks] == [("10.0.0.2", 9001)]
    assert written_hash in {entry[0] for entry in vortex_chat.storage_list_distributed()}

    session.query(DistributedFile).filter(DistributedFile.file_hash.in_([file_hash, written_hash])).delete(
        synchronize_session=False
    )
    session.commit()


def test_both_runtimes_see_one_unified_push_subscription(account):
    session, user_id, _device_id, _client_device_id = account
    endpoint = f"https://ntfy.test/{uuid.uuid4().hex}"
    session.add(
        UnifiedPushSubscription(
            user_id=user_id,
            endpoint=endpoint,
            app_id="org.vortex.messenger",
            created_at=WRITTEN_AT,
            failures=0,
            active=True,
        )
    )
    session.commit()

    assert vortex_chat.storage_unified_push_of(user_id) == [
        (endpoint, "org.vortex.messenger", *WRITTEN_UNIX, 0, True)
    ]

    vortex_chat.storage_record_unified_delivery(user_id, endpoint, 15, False)
    session.expire_all()
    stored = session.query(UnifiedPushSubscription).filter(UnifiedPushSubscription.endpoint == endpoint).one()
    assert (stored.failures, stored.active) == (15, False)

    written = f"https://ntfy.test/{uuid.uuid4().hex}"
    vortex_chat.storage_register_unified_push(user_id, written, "org.vortex.fork", *WRITTEN_UNIX, 0, True)
    session.expire_all()
    assert session.query(UnifiedPushSubscription).filter(UnifiedPushSubscription.endpoint == written).count() == 1

    assert vortex_chat.storage_unregister_unified_push(user_id, written) is True
    session.expire_all()
    assert session.query(UnifiedPushSubscription).filter(UnifiedPushSubscription.endpoint == written).count() == 0

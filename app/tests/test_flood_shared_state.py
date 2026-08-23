"""Флуд-контроль комнат в общем состоянии (крейт `vortex-ratelimit`).

Счёт сообщений и счёт срабатываний переехали из словарей воркера в общее
состояние, поэтому порог комнаты и «три срабатывания — бан» теперь означают то,
что заявлено, а не «порог × число воркеров». Здесь проверяется контракт счёта
(на случайных парах «комната+участник», чтобы прогон не зависел от прежних
запусков) и отдельно — что Python делает с вынесенным решением.

Обхода `TESTING` у флуд-контроля нет: он считает по паре «комната+участник», а
она у каждого теста своя.
"""

import secrets

import pytest

from app.chats.messages import flood
from app.security import ratelimit_backend as _ratelimit


def membership() -> tuple[int, int]:
    return 700_000_000 + secrets.randbelow(100_000_000), 800_000_000 + secrets.randbelow(100_000_000)


def flood_until_penalty(room_id: int, user_id: int, threshold: int) -> tuple[bool, int, bool]:
    verdict = (False, 0, False)
    for _ in range(threshold + 1):
        verdict = _ratelimit.flood_check(room_id, user_id, threshold)
    return verdict


class TestMessageWindow:
    def test_fifteen_messages_pass_and_the_sixteenth_does_not(self):
        room_id, user_id = membership()
        for _ in range(15):
            assert _ratelimit.flood_check(room_id, user_id, 15)[0] is False
        assert _ratelimit.flood_check(room_id, user_id, 15)[0] is True

    def test_a_room_that_names_no_threshold_gets_the_default_fifteen(self):
        room_id, user_id = membership()
        for _ in range(15):
            assert _ratelimit.flood_check(room_id, user_id, 0)[0] is False
        assert _ratelimit.flood_check(room_id, user_id, 0)[0] is True

    def test_a_room_with_a_lower_threshold_penalises_sooner(self):
        room_id, user_id = membership()
        for _ in range(5):
            assert _ratelimit.flood_check(room_id, user_id, 5)[0] is False
        assert _ratelimit.flood_check(room_id, user_id, 5)[0] is True

    def test_one_member_never_spends_the_budget_of_another(self):
        room_id, user_id = membership()
        assert flood_until_penalty(room_id, user_id, 5)[0] is True
        assert _ratelimit.flood_check(room_id, user_id + 1, 5)[0] is False
        assert _ratelimit.flood_check(room_id + 1, user_id, 5)[0] is False

    def test_a_forgotten_window_gives_the_member_a_fresh_budget(self):
        room_id, user_id = membership()
        assert flood_until_penalty(room_id, user_id, 5)[0] is True
        _ratelimit.flood_forget(room_id, user_id)
        assert _ratelimit.flood_check(room_id, user_id, 5)[0] is False


class TestStrikes:
    def test_the_third_penalty_earns_a_ban(self):
        room_id, user_id = membership()
        for expected in (1, 2):
            _, strikes, earns_a_ban = flood_until_penalty(room_id, user_id, 5)
            assert strikes == expected
            assert earns_a_ban is False
            _ratelimit.flood_forget(room_id, user_id)

        _, strikes, earns_a_ban = flood_until_penalty(room_id, user_id, 5)
        assert strikes == 3
        assert earns_a_ban is True

    def test_a_strike_outlives_the_window_that_earned_it(self):
        room_id, user_id = membership()
        assert flood_until_penalty(room_id, user_id, 5)[1] == 1
        _ratelimit.flood_forget(room_id, user_id)
        assert flood_until_penalty(room_id, user_id, 5)[1] == 2

    def test_one_membership_never_earns_a_strike_for_another(self):
        room_id, user_id = membership()
        flood_until_penalty(room_id, user_id, 5)
        assert flood_until_penalty(room_id, user_id + 1, 5)[1] == 1


class TestWhatPythonDoesWithTheVerdict:
    """Наказание, рассылку и запись в БД по-прежнему делает Python."""

    @pytest.fixture
    def member_user(self, room, two_users):
        from app.database import SessionLocal
        from app.models import User
        from app.models_rooms import RoomMember, RoomRole

        _, joiner = two_users
        db = SessionLocal()
        user = db.query(User).filter(User.username == joiner["username"]).first()
        assert user is not None
        member = RoomMember(room_id=room["id"], user_id=user.id, role=RoomRole.MEMBER)
        db.add(member)
        db.commit()
        db.refresh(member)
        yield db, user, member
        db.delete(member)
        db.commit()
        db.close()

    @pytest.mark.asyncio
    async def test_a_message_within_the_threshold_is_not_dropped(self, room, member_user, monkeypatch):
        db, user, _ = member_user
        monkeypatch.setattr(_ratelimit, "flood_check", lambda *_args: (False, 0, False))

        assert await flood.check_flood(room["id"], user, db) is False

    @pytest.mark.asyncio
    async def test_a_first_penalty_mutes_and_forgets_the_window(self, room, member_user, monkeypatch):
        db, user, member = member_user
        forgotten: list[tuple[int, int]] = []
        monkeypatch.setattr(_ratelimit, "flood_check", lambda *_args: (True, 1, False))
        monkeypatch.setattr(
            _ratelimit,
            "flood_forget",
            lambda room_id, user_id: forgotten.append((room_id, user_id)),
        )

        assert await flood.check_flood(room["id"], user, db) is True
        db.refresh(member)
        assert member.muted_until is not None
        assert member.is_banned is False
        assert forgotten == [(room["id"], user.id)]

    @pytest.mark.asyncio
    async def test_the_penalty_that_earns_a_ban_bans(self, room, member_user, monkeypatch):
        db, user, member = member_user
        monkeypatch.setattr(_ratelimit, "flood_check", lambda *_args: (True, 3, True))
        monkeypatch.setattr(_ratelimit, "flood_forget", lambda *_args: None)

        assert await flood.check_flood(room["id"], user, db) is True
        db.refresh(member)
        assert member.is_banned is True

    @pytest.mark.asyncio
    async def test_an_owner_is_never_counted_at_all(self, client, room, logged_user, monkeypatch):
        from app.database import SessionLocal
        from app.models import User

        counted: list[tuple] = []
        monkeypatch.setattr(
            _ratelimit,
            "flood_check",
            lambda *args: counted.append(args) or (True, 3, True),
        )

        db = SessionLocal()
        owner = db.query(User).filter(User.username == logged_user["username"]).first()
        assert owner is not None
        assert await flood.check_flood(room["id"], owner, db) is False
        assert counted == []
        db.close()

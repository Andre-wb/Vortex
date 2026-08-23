"""Общий счёт обращений (крейт `vortex-ratelimit`).

Тринадцать ограничителей частоты переехали из словарей процесса в общее
состояние: транспортные пароли, пакеты сплетен, чтения профиль-хранилища и
уведомления zero-knowledge, переводы, предпросмотр ссылок, помощник, конверты
репликации, обращения узлов федерации, push-прокси, раскрытие псевдонимов,
гостевые входы федерации, сохранение долей ключа и сигнальные сообщения. Туда же
переехали оба антиспам-детектора комнаты — повторы и ссылки. Здесь проверяется
контракт, который видят потребители: предел общий на предмет счёта, корзины не
тратят бюджет друг друга, окно скользит, а обращение, которое некому сосчитать,
отклоняется, а не пропускается.

Обход `TESTING=true` снимается в каждой проверке — иначе ограничитель выключен
и прогон не значил бы ничего.
"""

import secrets

import pytest

from app.chats import link_preview
from app.federation import replication
from app.push import bmp_push_proxy
from app.security import ratelimit_backend as _ratelimit
from app.security import zero_knowledge


@pytest.fixture(autouse=True)
def counting_is_on(monkeypatch):
    monkeypatch.setattr(_ratelimit, "_IS_TESTING", False)


def address() -> str:
    return f"198.51.100.{secrets.token_hex(6)}"


def account() -> int:
    return 900_000_000 + secrets.randbelow(100_000_000)


class TestTransportSecrets:
    def test_the_operator_limit_holds_for_the_address(self):
        client = address()
        for _ in range(3):
            assert _ratelimit.secrets_address_allowed(client, 3) is True
        assert _ratelimit.secrets_address_allowed(client, 3) is False

    def test_the_operator_limit_holds_for_the_account(self):
        user = account()
        for _ in range(3):
            assert _ratelimit.secrets_account_allowed(user, 3) is True
        assert _ratelimit.secrets_account_allowed(user, 3) is False

    def test_an_address_and_an_account_are_counted_apart(self):
        client = address()
        user = account()
        for _ in range(3):
            _ratelimit.secrets_address_allowed(client, 3)
        assert _ratelimit.secrets_address_allowed(client, 3) is False
        assert _ratelimit.secrets_account_allowed(user, 3) is True

    def test_a_limit_of_zero_lets_nobody_through(self):
        assert _ratelimit.secrets_address_allowed(address(), 0) is False


class TestGossip:
    def test_ten_packets_from_one_address_pass_and_the_eleventh_does_not(self):
        peer = address()
        for _ in range(10):
            assert _ratelimit.gossip_allowed(peer) is True
        assert _ratelimit.gossip_allowed(peer) is False

    def test_one_noisy_peer_never_silences_another(self):
        noisy = address()
        for _ in range(10):
            _ratelimit.gossip_allowed(noisy)
        assert _ratelimit.gossip_allowed(noisy) is False
        assert _ratelimit.gossip_allowed(address()) is True


class TestZeroKnowledge:
    def test_thirty_profile_lookups_pass_and_the_thirty_first_does_not(self):
        user = account()
        for _ in range(30):
            assert _ratelimit.vault_read_allowed(user) is True
        assert _ratelimit.vault_read_allowed(user) is False

    def test_sixty_notifications_from_one_sender_pass_and_the_sixty_first_does_not(self):
        sender = account()
        for index in range(60):
            assert _ratelimit.notification_sender_allowed(sender) is True, index
        assert _ratelimit.notification_sender_allowed(sender) is False

    def test_twenty_notifications_to_one_recipient_pass_and_the_twenty_first_does_not(self):
        sender = account()
        recipient = account()
        for _ in range(20):
            assert _ratelimit.notification_pair_allowed(sender, recipient) is True
        assert _ratelimit.notification_pair_allowed(sender, recipient) is False

    def test_one_recipient_never_spends_the_budget_of_another(self):
        sender = account()
        recipient = account()
        for _ in range(20):
            _ratelimit.notification_pair_allowed(sender, recipient)
        assert _ratelimit.notification_pair_allowed(sender, recipient) is False
        assert _ratelimit.notification_pair_allowed(sender, recipient + 1) is True

    def test_the_three_zero_knowledge_buckets_never_share_one_window(self):
        user = account()
        for _ in range(30):
            _ratelimit.vault_read_allowed(user)
        assert _ratelimit.vault_read_allowed(user) is False
        assert _ratelimit.notification_sender_allowed(user) is True
        assert _ratelimit.notification_pair_allowed(user, user) is True


class TestChatFeatures:
    def test_fifty_translations_an_hour_pass_and_the_fifty_first_does_not(self):
        user = account()
        for _ in range(50):
            assert _ratelimit.translation_allowed(user) is True
        assert _ratelimit.translation_allowed(user) is False

    def test_twenty_requests_to_the_assistant_pass_and_the_twenty_first_does_not(self):
        user = account()
        for _ in range(20):
            assert _ratelimit.assistant_allowed(user) is True
        assert _ratelimit.assistant_allowed(user) is False

    def test_thirty_previews_pass_for_an_account_and_for_an_address_apart(self):
        user = account()
        client = address()
        for _ in range(30):
            assert _ratelimit.preview_account_allowed(user) is True
        assert _ratelimit.preview_account_allowed(user) is False
        assert _ratelimit.preview_address_allowed(client) is True

    def test_translations_and_assistant_requests_are_counted_apart(self):
        user = account()
        for _ in range(20):
            _ratelimit.assistant_allowed(user)
        assert _ratelimit.assistant_allowed(user) is False
        assert _ratelimit.translation_allowed(user) is True


class TestFederation:
    def test_a_hundred_and_twenty_envelopes_pass_and_the_next_one_does_not(self):
        origin = address()
        for _ in range(120):
            assert _ratelimit.replication_allowed(origin) is True
        assert _ratelimit.replication_allowed(origin) is False

    def test_a_hundred_node_requests_pass_and_the_hundred_and_first_does_not(self):
        node = f"node-{secrets.token_hex(8)}"
        for _ in range(100):
            assert _ratelimit.node_allowed(node) is True
        assert _ratelimit.node_allowed(node) is False

    def test_one_node_purpose_never_spends_the_budget_of_another(self):
        client = address()
        for _ in range(100):
            _ratelimit.node_allowed(f"gossip:{client}")
        assert _ratelimit.node_allowed(f"gossip:{client}") is False
        assert _ratelimit.node_allowed(f"manifest:{client}") is True

    def test_envelopes_and_node_requests_are_counted_apart(self):
        origin = address()
        for _ in range(120):
            _ratelimit.replication_allowed(origin)
        assert _ratelimit.replication_allowed(origin) is False
        assert _ratelimit.node_allowed(origin) is True


class TestPushProxy:
    def test_sixty_registrations_pass_and_the_sixty_first_does_not(self):
        client = address()
        for _ in range(60):
            assert _ratelimit.push_register_allowed(client) is True
        assert _ratelimit.push_register_allowed(client) is False

    def test_registrations_and_wakes_are_counted_apart(self):
        client = address()
        for _ in range(60):
            _ratelimit.push_register_allowed(client)
        assert _ratelimit.push_register_allowed(client) is False
        assert _ratelimit.push_wake_allowed(client) is True


class TestPseudonymResolves:
    """Единственный ограничитель без предмета счёта — один бюджет на кластер."""

    def test_every_caller_spends_from_one_shared_budget(self):
        assert _ratelimit.pseudonym_resolve_allowed(2, 1) is True
        assert _ratelimit.pseudonym_resolve_allowed(2, 1) is True
        assert _ratelimit.pseudonym_resolve_allowed(2, 1) is False

    def test_neither_a_zero_limit_nor_a_zero_window_lets_anybody_through(self):
        assert _ratelimit.pseudonym_resolve_allowed(0, 60) is False
        assert _ratelimit.pseudonym_resolve_allowed(100, 0) is False


class TestHostileSubjects:
    """Предмет счёта из тела запроса не становится ключом Redis как есть."""

    def test_a_subject_no_socket_could_produce_is_refused_rather_than_counted(self):
        for hostile in ["", "10.0.0.1 ", "10.0.0.1\n", "a" * 129]:
            assert _ratelimit.gossip_allowed(hostile) is False
            assert _ratelimit.node_allowed(hostile) is False
            assert _ratelimit.replication_allowed(hostile) is False
            assert _ratelimit.push_register_allowed(hostile) is False


class TestShortCircuit:
    """Две корзины на одной точке: вторая не тратится, пока первая не пропустила."""

    def test_an_exhausted_sender_never_spends_the_pair_budget(
        self, client, logged_user, monkeypatch
    ):
        charged: list[tuple[int, int]] = []
        monkeypatch.setattr(zero_knowledge, "_has_relationship", lambda *_args: True)
        monkeypatch.setattr(
            zero_knowledge._ratelimit, "notification_sender_allowed", lambda _user: False
        )
        monkeypatch.setattr(
            zero_knowledge._ratelimit,
            "notification_pair_allowed",
            lambda user, recipient: charged.append((user, recipient)) or True,
        )

        response = client.post(
            "/api/zk/notifications",
            json={
                "recipient_id": 4242,
                "ephemeral_pub": secrets.token_hex(32),
                "ciphertext": secrets.token_hex(16),
            },
            headers=logged_user["headers"],
        )
        assert response.status_code == 429
        assert charged == []

    def test_an_exhausted_account_never_spends_the_address_budget(
        self, client, logged_user, monkeypatch
    ):
        charged: list[str] = []
        monkeypatch.setattr(link_preview._ratelimit, "preview_account_allowed", lambda _user: False)
        monkeypatch.setattr(
            link_preview._ratelimit,
            "preview_address_allowed",
            lambda address: charged.append(address) or True,
        )

        response = client.get(
            "/api/link-preview",
            params={"url": "https://example.com/"},
            headers=logged_user["headers"],
        )
        assert response.status_code == 429
        assert charged == []


class TestOverHttp:
    """Роуты считают обращения только вне TESTING — иначе ограничитель выключен."""

    def _csrf(self, client) -> dict:
        token = client.get("/api/authentication/csrf-token").json().get("csrf_token", "")
        return {"X-CSRF-Token": token}

    def _register(self, client) -> int:
        return client.post(
            "/api/push-proxy/register",
            json={
                "categories": [1],
                "token": secrets.token_hex(8),
                "endpoint": "https://fcm.googleapis.com/fcm/send/abc",
            },
            headers=self._csrf(client),
        ).status_code

    def test_the_sixty_first_registration_from_one_client_answers_429(self, client, monkeypatch):
        client_address = address()
        monkeypatch.setattr(bmp_push_proxy, "_client_ip", lambda _request: client_address)

        for index in range(60):
            assert self._register(client) == 200, index
        assert self._register(client) == 429

    def test_a_client_the_shared_state_cannot_count_is_refused(self, client, monkeypatch):
        monkeypatch.setattr(bmp_push_proxy, "_client_ip", lambda _request: address())
        monkeypatch.setattr(_ratelimit, "push_register_allowed", lambda _address: False)

        assert self._register(client) == 429

    def test_the_limiter_is_off_while_testing(self, client, monkeypatch):
        client_address = address()
        monkeypatch.setattr(bmp_push_proxy, "_client_ip", lambda _request: client_address)
        monkeypatch.setattr(_ratelimit, "_IS_TESTING", True)

        for _ in range(65):
            assert self._register(client) == 200

    def test_the_envelope_endpoint_answers_429_when_the_window_is_full(self, client, monkeypatch):
        origin = address()
        monkeypatch.setattr(replication, "raw_ip_for_ratelimit", lambda _request: origin)
        for _ in range(120):
            _ratelimit.replication_allowed(origin)

        response = client.post(
            "/api/federation/envelopes",
            json={
                "origin_pubkey": "ab" * 32,
                "room_id_origin": 1,
                "sender_ts": 0,
                "payload": {"kind": "test"},
                "signature": "cd" * 64,
            },
            headers=self._csrf(client),
        )
        assert response.status_code == 429


class TestGuestLogins:
    def test_thirty_guest_logins_from_one_address_pass_and_the_thirty_first_does_not(self):
        source = address()
        for _ in range(30):
            assert _ratelimit.guest_login_allowed(source) is True
        assert _ratelimit.guest_login_allowed(source) is False

    def test_one_noisy_address_never_locks_out_another(self):
        noisy = address()
        for _ in range(30):
            _ratelimit.guest_login_allowed(noisy)
        assert _ratelimit.guest_login_allowed(noisy) is False
        assert _ratelimit.guest_login_allowed(address()) is True

    def test_an_address_nobody_can_count_is_refused(self):
        assert _ratelimit.guest_login_allowed("") is False


class TestShardStores:
    def test_one_hundred_and_twenty_stores_pass_and_the_next_one_does_not(self):
        source = address()
        for _ in range(120):
            assert _ratelimit.shard_store_allowed(source) is True
        assert _ratelimit.shard_store_allowed(source) is False

    def test_guest_logins_and_shard_stores_are_counted_apart(self):
        source = address()
        for _ in range(30):
            _ratelimit.guest_login_allowed(source)
        assert _ratelimit.guest_login_allowed(source) is False
        assert _ratelimit.shard_store_allowed(source) is True


class TestSignallingMessages:
    def test_one_hundred_messages_a_second_pass_and_the_next_one_does_not(self):
        user = account()
        for _ in range(100):
            assert _ratelimit.signal_allowed(user) is True
        assert _ratelimit.signal_allowed(user) is False

    def test_one_noisy_account_never_silences_another(self):
        noisy = account()
        for _ in range(100):
            _ratelimit.signal_allowed(noisy)
        assert _ratelimit.signal_allowed(noisy) is False
        assert _ratelimit.signal_allowed(account()) is True


class TestRepeatSpam:
    def room(self) -> int:
        return 700_000_000 + secrets.randbelow(100_000_000)

    def test_two_copies_pass_and_the_third_is_spam(self):
        room, user = self.room(), account()
        assert _ratelimit.repeat_spam(room, user, "стоп") == (False, "clean")
        assert _ratelimit.repeat_spam(room, user, "стоп") == (False, "clean")
        assert _ratelimit.repeat_spam(room, user, "стоп") == (True, "spam")

    def test_different_messages_never_add_up_to_a_repeat(self):
        room, user = self.room(), account()
        for text in ("раз", "два", "три", "четыре"):
            assert _ratelimit.repeat_spam(room, user, text) == (False, "clean")

    def test_letter_case_and_surrounding_space_do_not_hide_a_repeat(self):
        room, user = self.room(), account()
        _ratelimit.repeat_spam(room, user, "Стоп")
        _ratelimit.repeat_spam(room, user, "  СТОП ")
        assert _ratelimit.repeat_spam(room, user, "стоп") == (True, "spam")

    def test_one_member_never_answers_for_another(self):
        room, user = self.room(), account()
        _ratelimit.repeat_spam(room, user, "стоп")
        _ratelimit.repeat_spam(room, user, "стоп")
        assert _ratelimit.repeat_spam(room, account(), "стоп") == (False, "clean")
        assert _ratelimit.repeat_spam(self.room(), user, "стоп") == (False, "clean")

    def test_a_caught_member_starts_from_scratch(self):
        room, user = self.room(), account()
        for _ in range(3):
            _ratelimit.repeat_spam(room, user, "стоп")
        assert _ratelimit.repeat_spam(room, user, "стоп") == (False, "clean")


class TestLinkSpam:
    def room(self) -> int:
        return 800_000_000 + secrets.randbelow(100_000_000)

    def test_two_links_pass_and_the_third_is_spam(self):
        room, user = self.room(), account()
        assert _ratelimit.link_spam(room, user) == (False, "clean")
        assert _ratelimit.link_spam(room, user) == (False, "clean")
        assert _ratelimit.link_spam(room, user) == (True, "spam")

    def test_one_member_never_answers_for_another(self):
        room, user = self.room(), account()
        _ratelimit.link_spam(room, user)
        _ratelimit.link_spam(room, user)
        assert _ratelimit.link_spam(room, account()) == (False, "clean")

    def test_a_caught_member_starts_the_window_from_scratch(self):
        room, user = self.room(), account()
        for _ in range(3):
            _ratelimit.link_spam(room, user)
        assert _ratelimit.link_spam(room, user) == (False, "clean")

    def test_repeats_and_links_are_counted_apart(self):
        room, user = self.room(), account()
        for _ in range(2):
            _ratelimit.link_spam(room, user)
        assert _ratelimit.repeat_spam(room, user, "ссылка") == (False, "clean")


def _member():
    class Member:
        id = 42
        username = "member"
        display_name = "Member"

    return Member()


class TestAntispamWithoutSharedState:
    """Контракт fail-closed: сообщение, которое некому сосчитать, не доходит."""

    async def _drop(self, monkeypatch, verdict) -> bool:
        from app.bots import antispam_bot

        monkeypatch.setattr(_ratelimit, "repeat_spam", lambda *_: verdict)
        posted = []

        async def remember(*args, **kwargs):
            posted.append(args)

        monkeypatch.setattr(antispam_bot, "antispam_bot_message", remember)
        held = await antispam_bot.check_repeat_spam(1, _member(), "текст", None)
        return held, posted

    @pytest.mark.asyncio
    async def test_a_message_nobody_can_count_is_held_back(self, monkeypatch):
        held, _posted = await self._drop(monkeypatch, (True, "unavailable"))
        assert held is True

    @pytest.mark.asyncio
    async def test_a_message_held_for_want_of_counting_gets_no_bot_warning(self, monkeypatch):
        _held, posted = await self._drop(monkeypatch, (True, "unavailable"))
        assert posted == []

    @pytest.mark.asyncio
    async def test_a_message_caught_as_spam_does_get_a_bot_warning(self, monkeypatch):
        _held, posted = await self._drop(monkeypatch, (True, "spam"))
        assert len(posted) == 1

    @pytest.mark.asyncio
    async def test_a_link_nobody_can_count_is_held_back_without_a_warning(self, monkeypatch):
        from app.bots import antispam_bot
        from app.models_rooms import RoomRole

        monkeypatch.setattr(_ratelimit, "link_spam", lambda *_: (True, "unavailable"))
        posted = []

        async def remember(*args, **kwargs):
            posted.append(args)

        monkeypatch.setattr(antispam_bot, "antispam_bot_message", remember)
        held = await antispam_bot.check_link_spam(1, _member(), "см. https://example.test", RoomRole.MEMBER, None)
        assert (held, posted) == (True, [])

"""Разделяемое состояние доставки: память о повторах и очереди для офлайн-получателей.

Записи живут в Rust (`vortex-delivery`), Python зовёт их через
`app/peer/delivery_backend.py`. Здесь проверяется контракт, который видят
потребители: что считается повтором, что получит подключившийся участник и что
происходит, когда общего состояния нет.
"""

import secrets

import pytest

from app.peer import delivery_backend as _delivery


@pytest.fixture
def tag():
    return secrets.token_hex(8)


@pytest.fixture
def room_id():
    return secrets.randbelow(1_000_000) + 8_000_000


@pytest.fixture
def reader():
    return secrets.randbelow(100_000) + 8_100_000


class TestDeduplication:
    def test_a_first_sighting_is_not_a_repeat(self, tag):
        assert _delivery.is_repeat(f"{tag}-first") is False

    def test_a_second_sighting_is_a_repeat(self, tag):
        assert _delivery.is_repeat(f"{tag}-second") is False
        assert _delivery.is_repeat(f"{tag}-second") is True

    def test_different_identifiers_do_not_shadow_each_other(self, tag):
        assert _delivery.is_repeat(f"{tag}-a") is False
        assert _delivery.is_repeat(f"{tag}-b") is False
        assert _delivery.is_repeat(f"{tag}-a") is True

    def test_an_identifier_outside_the_alphabet_is_refused(self):
        with pytest.raises(ValueError):
            _delivery.is_repeat("has a space")

    def test_an_over_long_identifier_is_refused(self):
        with pytest.raises(ValueError):
            _delivery.is_repeat("a" * 129)


class TestRoomQueue:
    def test_a_deposited_message_is_collected_once(self, room_id, reader):
        _delivery.room_deposit(room_id, [reader], {"type": "message", "id": 1})
        assert _delivery.room_collect(room_id, reader) == [{"type": "message", "id": 1}]
        assert _delivery.room_collect(room_id, reader) == []

    def test_order_of_deposit_is_the_order_of_collection(self, room_id, reader):
        for n in range(4):
            _delivery.room_deposit(room_id, [reader], {"n": n})
        assert _delivery.room_collect(room_id, reader) == [{"n": n} for n in range(4)]

    def test_one_deposit_reaches_every_named_reader(self, room_id, reader):
        readers = [reader, reader + 1, reader + 2]
        _delivery.room_deposit(room_id, readers, {"all": True})
        for uid in readers:
            assert _delivery.room_collect(room_id, uid) == [{"all": True}]

    def test_a_reader_sees_only_their_own_room(self, room_id, reader):
        _delivery.room_deposit(room_id, [reader], {"r": room_id})
        assert _delivery.room_collect(room_id + 1, reader) == []
        assert _delivery.room_collect(room_id, reader + 1) == []
        assert _delivery.room_collect(room_id, reader) == [{"r": room_id}]

    def test_an_empty_reader_list_deposits_nothing(self, room_id, reader):
        _delivery.room_deposit(room_id, [], {"nobody": True})
        assert _delivery.room_collect(room_id, reader) == []

    def test_a_payload_carrying_colons_survives_the_round_trip(self, room_id, reader):
        payload = {"url": "https://example.com:8443/a:b", "text": "1:2:3"}
        _delivery.room_deposit(room_id, [reader], payload)
        assert _delivery.room_collect(room_id, reader) == [payload]

    def test_a_room_number_must_be_positive(self, reader):
        with pytest.raises(ValueError):
            _delivery.room_deposit(0, [reader], {})


class TestNotificationQueue:
    def test_a_deposited_notification_is_collected_once(self, reader):
        _delivery.notification_deposit(reader, {"type": "mention"})
        assert _delivery.notification_collect(reader) == [{"type": "mention"}]
        assert _delivery.notification_collect(reader) == []

    def test_order_of_deposit_is_the_order_of_collection(self, reader):
        for n in range(3):
            _delivery.notification_deposit(reader, {"n": n})
        assert _delivery.notification_collect(reader) == [{"n": n} for n in range(3)]

    def test_a_reader_sees_only_their_own_queue(self, reader):
        _delivery.notification_deposit(reader, {"mine": True})
        assert _delivery.notification_collect(reader + 1) == []
        assert _delivery.notification_collect(reader) == [{"mine": True}]


class TestUnavailableSharedState:
    """Отказ общего состояния виден наружу, а не проглатывается.

    Решение владельца 2026-08-22 — строго fail-closed на всех трёх сторах,
    включая проверку на повтор.
    """

    def test_every_operation_refuses_when_the_shared_state_is_sealed(
        self, monkeypatch, room_id, reader, tag
    ):
        import vortex_chat

        def sealed(*_args, **_kwargs):
            raise RuntimeError("общее состояние доставки недоступно — операция не выполнена")

        for name in (
            "delivery_is_repeat",
            "delivery_seen_count",
            "delivery_room_deposit",
            "delivery_room_collect",
            "delivery_room_sweep",
            "delivery_room_tally",
            "delivery_notification_deposit",
            "delivery_notification_collect",
            "delivery_notification_tally",
        ):
            monkeypatch.setattr(vortex_chat, name, sealed)

        refusals = (
            lambda: _delivery.is_repeat(f"{tag}-sealed"),
            lambda: _delivery.seen_count(),
            lambda: _delivery.room_deposit(room_id, [reader], {}),
            lambda: _delivery.room_collect(room_id, reader),
            lambda: _delivery.room_sweep(),
            lambda: _delivery.room_tally(),
            lambda: _delivery.notification_deposit(reader, {}),
            lambda: _delivery.notification_collect(reader),
            lambda: _delivery.notification_tally(),
        )
        for call in refusals:
            with pytest.raises(_delivery.DeliveryUnavailableError):
                call()

    def test_a_deposit_to_nobody_does_not_touch_the_shared_state(self, monkeypatch, room_id):
        import vortex_chat

        def sealed(*_args, **_kwargs):
            raise RuntimeError("общее состояние доставки недоступно — операция не выполнена")

        monkeypatch.setattr(vortex_chat, "delivery_room_deposit", sealed)
        _delivery.room_deposit(room_id, [], {"nobody": True})

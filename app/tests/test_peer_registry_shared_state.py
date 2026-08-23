"""Разделяемое состояние реестра узлов.

Реестр живёт в Rust (`vortex-net`), Python зовёт его через
`app/peer/peer_registry_backend.py`. До этого среза реестра было два —
Rust-овый внутри UDP-обнаружения и Python-словарь, синхронизируемый опросом;
здесь проверяется контракт единственного оставшегося.
"""

import secrets

import pytest

from app.peer import peer_registry_backend as _peers
from app.peer.peer_models import PeerRegistry


@pytest.fixture
def address():
    return f"10.{secrets.randbelow(200) + 30}.{secrets.randbelow(256)}.{secrets.randbelow(254) + 1}"


@pytest.fixture
def registry():
    return PeerRegistry()


class TestObserving:
    def test_a_heard_peer_is_found_again(self, registry, address):
        assert registry.update(address, "one", 8000) is True
        found = registry.get(address)
        assert found.name == "one"
        assert found.port == 8000
        assert found.online is True

    def test_hearing_a_known_peer_again_is_not_news(self, registry, address):
        registry.update(address, "two", 8000)
        assert registry.update(address, "two", 8001) is False
        assert registry.get(address).port == 8001

    def test_an_unknown_address_names_no_peer(self, registry, address):
        assert registry.get(address) is None

    def test_a_key_survives_a_silent_refresh(self, registry, address):
        key = secrets.token_hex(32)
        registry.update(address, "three", 8000, key)
        registry.update(address, "three", 8000, None)
        found = registry.get(address)
        assert found.node_pubkey_hex == key
        assert found.has_encryption() is True

    def test_a_key_of_the_wrong_shape_is_not_kept(self, registry, address):
        registry.update(address, "four", 8000, "too-short")
        assert registry.get(address).node_pubkey_hex is None

    def test_an_address_that_is_not_one_is_refused(self, registry):
        assert registry.update("example.com", "name", 8000) is False
        assert registry.get("not-an-ip") is None

    def test_a_port_outside_the_range_is_refused(self, registry, address):
        assert registry.update(address, "name", 0) is False


class TestLiveness:
    def test_a_heard_peer_is_among_the_living(self, registry, address):
        registry.update(address, "live", 8000)
        assert address in [peer.ip for peer in registry.active()]

    def test_forgetting_the_dead_keeps_the_living(self, registry, address):
        registry.update(address, "here", 8000)
        registry.cleanup()
        assert registry.get(address) is not None

    def test_a_peer_past_the_timeout_is_forgotten(self, registry, address):
        from app.config import Config

        was = float(Config.PEER_TIMEOUT_SEC)
        _peers.set_timeout(0.01)
        try:
            registry.update(address, "gone", 8000)
            import time

            time.sleep(0.05)
            assert address not in [peer.ip for peer in registry.active()]
            registry.cleanup()
            assert registry.get(address) is None
        finally:
            _peers.set_timeout(was)


class TestPeerRooms:
    def test_rooms_are_told_with_the_peer_that_named_them(self, registry, address):
        registry.update(address, "host", 8000)
        registry.set_peer_rooms(address, [{"id": 1, "name": "public"}])
        told = [row for row in registry.get_all_peer_rooms() if row["peer_ip"] == address]
        assert told == [
            {"id": 1, "name": "public", "peer_ip": address, "peer_name": "host", "peer_port": 8000}
        ]

    def test_a_peer_without_rooms_is_not_told(self, registry, address):
        registry.update(address, "quiet", 8000)
        assert address not in [row["peer_ip"] for row in registry.get_all_peer_rooms()]

    def test_a_later_room_list_replaces_the_earlier_one(self, registry, address):
        registry.update(address, "busy", 8000)
        registry.set_peer_rooms(address, [{"id": 1}])
        registry.set_peer_rooms(address, [{"id": 2}])
        told = [row for row in registry.get_all_peer_rooms() if row["peer_ip"] == address]
        assert [row["id"] for row in told] == [2]


class TestVirtualRoomIds:
    def test_ids_are_handed_out_going_down(self):
        first = _peers.next_virtual_room()
        assert first < 0
        assert _peers.next_virtual_room() == first - 1

    def test_no_two_callers_get_the_same_id(self):
        handed = [_peers.next_virtual_room() for _ in range(8)]
        assert len(set(handed)) == len(handed)

    def test_a_restored_id_is_never_handed_out_again(self):
        floor = _peers.next_virtual_room() - 1000
        _peers.reserve_virtual_room(floor)
        assert _peers.next_virtual_room() == floor - 1

    def test_a_local_room_number_reserves_nothing(self):
        _peers.reserve_virtual_room(7)
        assert _peers.next_virtual_room() < 0

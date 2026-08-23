"""Разделяемое состояние пуш-прокси BMP: регистрации токенов по категориям.

Записи живут в Rust (`vortex-bmp`), Python зовёт их через
`app/push/push_registry_backend.py`. Приватность не меняется: категория —
единственное, что прокси знает о подписчике.
"""

import json
import secrets

import pytest

from app.push import push_registry_backend as _registry


def _token():
    return json.dumps({"auth": secrets.token_hex(16)})


@pytest.fixture
def token():
    return _token()


@pytest.fixture
def category():
    return secrets.randbelow(256)


def _endpoint(tag=""):
    return f"https://push.example/{tag or secrets.token_hex(8)}"


class TestRegistration:
    def test_a_registered_token_is_found_in_its_category(self, token, category):
        where = _endpoint()
        _registry.register([category], token, where)
        assert (where, token) in _registry.registrations(category)

    def test_a_token_reaches_every_category_it_named(self, token):
        named = [secrets.randbelow(256) for _ in range(3)]
        where = _endpoint()
        _registry.register(named, token, where)
        for one in named:
            assert (where, token) in _registry.registrations(one)

    def test_the_same_token_twice_is_held_once(self, token, category):
        _registry.register([category], token, _endpoint("first"))
        _registry.register([category], token, _endpoint("second"))
        held = [pair for pair in _registry.registrations(category) if pair[1] == token]
        assert held == [(_endpoint("second"), token)]

    def test_an_unregistered_token_leaves_every_category(self, token):
        named = [secrets.randbelow(256) for _ in range(2)]
        _registry.register(named, token, _endpoint())
        _registry.unregister(token)
        for one in named:
            assert token not in [pair[1] for pair in _registry.registrations(one)]

    def test_unregistering_an_unknown_token_removes_nothing(self, token):
        assert _registry.unregister(token) == 0

    def test_tokens_do_not_shadow_each_other(self, category):
        left, right = _token(), _token()
        _registry.register([category], left, _endpoint("left"))
        _registry.register([category], right, _endpoint("right"))
        held = [pair[1] for pair in _registry.registrations(category)]
        assert left in held
        assert right in held


class TestCategories:
    def test_a_category_past_the_range_wraps_around(self, token):
        _registry.register([256], token, _endpoint())
        assert token in [pair[1] for pair in _registry.registrations(0)]

    def test_a_negative_category_wraps_the_way_python_wraps_it(self, token):
        _registry.register([-1], token, _endpoint())
        assert token in [pair[1] for pair in _registry.registrations(255)]

    def test_naming_no_category_is_refused(self, token):
        with pytest.raises(ValueError):
            _registry.register([], token, _endpoint())

    def test_a_short_token_is_refused(self, category):
        with pytest.raises(ValueError):
            _registry.register([category], "abc", _endpoint())

    def test_an_endpoint_with_a_space_is_refused(self, token, category):
        with pytest.raises(ValueError):
            _registry.register([category], token, "https://a b.example/x")


class TestWake:
    def test_a_wake_names_the_tokens_of_its_category(self, token, category):
        where = _endpoint()
        _registry.register([category], token, where)
        assert (where, token) in _registry.wake(category)

    def test_a_wake_is_counted(self, category):
        before = _registry.tally()["total_wakes"]
        _registry.wake(category)
        assert _registry.tally()["total_wakes"] == before + 1

    def test_a_tally_counts_the_tokens_it_holds(self, token, category):
        before = _registry.tally()["total_tokens"]
        _registry.register([category], token, _endpoint())
        assert _registry.tally()["total_tokens"] >= before + 1

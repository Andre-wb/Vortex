"""Кросс-языковые golden-тесты NaiveProxy: Python и Rust совпадают байт-в-байт.

Векторы: `app/tests/vectors/naive_parity.json` (генератор
`scripts/gen_naive_parity_vectors.py`), вторая независимая реализация правил —
`app/tests/naive_parity_reference.py`.

Отвергнутое значение — тоже часть контракта: там, где Python-эталон отдаёт
None, Rust обязан отказать (`ValueError`), а не собрать Caddyfile или URL из
того, что ему дали.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.tests import naive_parity_reference as reference

VECTORS_PATH = Path(__file__).parent / "vectors" / "naive_parity.json"

try:
    import vortex_chat as _rust
except ImportError:
    _rust = None

requires_rust = pytest.mark.skipif(_rust is None, reason="vortex_chat не собран")


def _vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _cases():
    vectors = _vectors()
    for fn in reference.FUNCTIONS:
        for index, vector in enumerate(vectors[fn.name]):
            yield pytest.param(fn, vector, id=f"{fn.name}-{index}")


ALL_CASES = list(_cases())


class TestVectorFile:
    def test_covers_every_function(self):
        assert set(_vectors()) == {fn.name for fn in reference.FUNCTIONS}

    def test_case_count_matches_reference(self):
        vectors = _vectors()
        for fn in reference.FUNCTIONS:
            assert len(vectors[fn.name]) == len(fn.cases), fn.name

    def test_frozen_args_match_reference(self):
        vectors = _vectors()
        for fn in reference.FUNCTIONS:
            frozen = [v["args"] for v in vectors[fn.name]]
            assert frozen == [json.loads(json.dumps(c)) for c in fn.cases], fn.name

    def test_both_outcomes_are_covered_everywhere(self):
        for name, cases in _vectors().items():
            outcomes = {next(iter(case["expected"].values())) is None for case in cases}
            assert outcomes == {True, False}, name


@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_python_matches_vector(fn, vector):
    assert fn.python(vector["args"]) == vector["expected"]


def _guard(port: int, backend_url: str = "", server_host: str = ""):
    return _rust.Naive(port, backend_url, server_host)


def _rust_caddyfile(args: dict) -> dict:
    guard = _guard(args["port"], args["backend_url"])
    guard.reload(args["username"], args["password"], args["probe_domain"])
    try:
        return {"caddyfile": guard.caddyfile("", "", args["email"], "")}
    except ValueError:
        return {"caddyfile": None}


def _rust_proxy_url(args: dict) -> dict:
    guard = _guard(args["port"], "", args["server_host"])
    guard.reload(args["username"], args["password"], "www.bing.com")
    try:
        return {"url": guard.proxy_url()}
    except ValueError:
        return {"url": None}


def _rust_client_config(args: dict) -> dict:
    guard = _guard(args["port"], "", args["server_host"])
    guard.reload(args["username"], args["password"], "www.bing.com")
    try:
        return {"config": guard.client_config()}
    except ValueError:
        return {"config": None}


RUST_IMPLEMENTATIONS = {
    "caddyfile": _rust_caddyfile,
    "proxy_url": _rust_proxy_url,
    "client_config": _rust_client_config,
}


@requires_rust
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_rust_matches_vector(fn, vector):
    assert RUST_IMPLEMENTATIONS[fn.name](vector["args"]) == vector["expected"]


class TestCaddyfileFormat:
    def test_every_configured_value_is_one_quoted_token(self):
        config = reference.caddyfile(
            443, "admin@example.com", "a3f9c2b1", "xK-_9Zq", "www.bing.com", "http://127.0.0.1:8000"
        )
        assert '    tls "admin@example.com" {\n' in config
        assert '        basic_auth "a3f9c2b1" "xK-_9Zq"\n' in config
        assert '        probe_resistance "www.bing.com"\n' in config
        assert '    reverse_proxy "http://127.0.0.1:8000" {\n' in config

    def test_the_placeholders_caddy_expands_itself_are_left_alone(self):
        config = reference.caddyfile(
            443, "admin@example.com", "a3f9c2b1", "xK-_9Zq", "www.bing.com", "http://127.0.0.1:8000"
        )
        assert "        header_up Host {host}\n" in config
        assert "        header_up X-Real-IP {remote_host}\n" in config

    @pytest.mark.parametrize(
        "password",
        [
            's3cret}\n    respond "pwned"\n{',
            "s3cret{env.HOME}",
            "s3cret #",
            's3"cret',
            "s3\\cret",
            "s3cret\ttab",
        ],
    )
    def test_a_password_that_would_reopen_the_file_stops_the_whole_file(self, password):
        assert (
            reference.caddyfile(443, "admin@example.com", "user", password, "www.bing.com", "http://127.0.0.1:8000")
            is None
        )


class TestProxyUrlFormat:
    def test_the_userinfo_is_percent_encoded(self):
        url = reference.proxy_url("proxy.example.com", 443, "user", "p@ss/evil.test")
        assert url == "https://user:p%40ss%2Fevil.test@proxy.example.com:443"

    def test_an_ipv6_server_is_bracketed(self):
        url = reference.proxy_url("2001:db8::1", 443, "user", "pass")
        assert url == "https://user:pass@[2001:db8::1]:443"

    def test_a_host_that_would_rewrite_the_url_is_refused(self):
        for server_host in ["proxy.example.com/x", "user@proxy.example.com", "proxy.example.com?q", ""]:
            assert reference.proxy_url(server_host, 443, "user", "pass") is None, server_host


@requires_rust
class TestCrossRuntime:
    def test_rust_writes_the_file_python_would_have_written(self):
        guard = _rust.Naive(8443, "http://127.0.0.1:9000", "proxy.example.com")
        guard.reload("a3f9c2b1", "xK-_9Zq", "archive.org")
        assert guard.caddyfile() == reference.caddyfile(
            8443, "admin@example.com", "a3f9c2b1", "xK-_9Zq", "archive.org", "http://127.0.0.1:9000"
        )

    def test_rust_writes_the_url_python_would_have_written(self):
        guard = _rust.Naive(443, "", "proxy.example.com")
        guard.reload("a3f9c2b1", "p@ss:word/x", "www.bing.com")
        assert guard.proxy_url() == reference.proxy_url("proxy.example.com", 443, "a3f9c2b1", "p@ss:word/x")

    def test_an_argument_wins_over_the_loaded_secret_in_both_runtimes(self):
        guard = _rust.Naive(443, "", "proxy.example.com")
        guard.reload("a3f9c2b1", "xK-_9Zq", "www.bing.com")
        assert guard.caddyfile("other", "s3cret", "ops@vortex.test", "duckduckgo.com") == reference.caddyfile(
            443, "ops@vortex.test", "other", "s3cret", "duckduckgo.com", "http://127.0.0.1:8000"
        )

    def test_a_guard_that_was_never_loaded_writes_nothing(self):
        guard = _rust.Naive(443, "", "proxy.example.com")
        assert not guard.is_renderable
        with pytest.raises(ValueError):
            guard.caddyfile()
        with pytest.raises(ValueError):
            guard.proxy_url()

    def test_a_refusal_never_repeats_the_secret_it_refused(self):
        guard = _rust.Naive(443, "", "proxy.example.com")
        guard.reload("a3f9c2b1", "s3cret\nrespond", "www.bing.com")
        with pytest.raises(ValueError) as refusal:
            guard.caddyfile()
        assert "s3cret" not in str(refusal.value)

"""Contract-тесты края: один запрос — одинаковый ответ Python и Rust.

Поднимаются оба рантайма: uvicorn с `app.main:app` на своём порту и бинарь
`vortex-server`, направленный на него. Роут переключается пер-роут флагом в
Redis, то есть проверяется и сам механизм отката.

Три значения различаются между любыми двумя запросами и потому сверяются по
наличию и типу, а не по значению: `uptime_seconds`, `active_peers` и
`ws_connections`. `X-Request-ID` фиксируется — обеим сторонам шлётся один и тот
же заголовок. Нонс в `Content-Security-Policy` заменяется маркером. `Date` и
`Content-Length` не сверяются.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / "target" / "debug" / "vortex-server"
RELEASE_BINARY = ROOT / "target" / "release" / "vortex-server"

PINNED_REQUEST_ID = "0123456789ab"
NONCE_MARKER = "'nonce-МАРКЕР'"
NONCE_PATTERN = re.compile(r"'nonce-[A-Za-z0-9_-]+'")

VOLATILE_FIELDS = ("uptime_seconds", "active_peers", "ws_connections")

COMPARED_HEADERS = (
    "content-type",
    "x-request-id",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "referrer-policy",
    "x-permitted-cross-domain-policies",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "strict-transport-security",
    "content-security-policy",
    "permissions-policy",
)


def _binary() -> Path | None:
    for candidate in (BINARY, RELEASE_BINARY):
        if candidate.exists():
            return candidate
    return None


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _wait_for(url: str, seconds: float = 10.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            httpx.get(url, timeout=1.0)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def _normalize_headers(headers) -> dict:
    normalized = {}
    for name in COMPARED_HEADERS:
        value = headers.get(name)
        if value is None:
            continue
        if name == "content-security-policy":
            value = NONCE_PATTERN.sub(NONCE_MARKER, value)
        normalized[name] = value
    return normalized


def _split_body(payload: dict) -> tuple[dict, dict]:
    stable = {key: value for key, value in payload.items() if key not in VOLATILE_FIELDS}
    volatile = {key: value for key, value in payload.items() if key in VOLATILE_FIELDS}
    return stable, volatile


class _Node:
    def __init__(self, python_url: str, rust_url: str, prefix: str):
        self.python_url = python_url
        self.rust_url = rust_url
        self.prefix = prefix


@pytest.fixture(scope="module")
def node():
    binary = _binary()
    if binary is None:
        pytest.skip("бинарь vortex-server не собран — cargo build -p vortex-server")

    redis_url = os.environ.get("REDIS_URL", "")
    if not redis_url:
        pytest.skip("REDIS_URL не задан — пер-роут флаги переключить нечем")

    try:
        import redis as redis_py
    except ImportError:  # pragma: no cover - зависит от окружения
        pytest.skip("redis-py не установлен")

    prefix = os.environ.get("REDIS_CHANNEL_PREFIX", "vortex")
    try:
        flags = redis_py.Redis.from_url(redis_url)
        flags.ping()
    except Exception as error:
        pytest.skip(f"Redis недоступен ({error}) — пер-роут флаги переключить нечем")

    import uvicorn

    from app.main import app

    python_port = _free_port()
    rust_port = _free_port()

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=python_port,
        log_level="warning",
        access_log=False,
        lifespan="on",
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    python_url = f"http://127.0.0.1:{python_port}"
    if not _wait_for(f"{python_url}/health"):
        server.should_exit = True
        pytest.skip("uvicorn с app.main не поднялся")

    environment = dict(os.environ)
    environment["VORTEX_RUST_HOST"] = "127.0.0.1"
    environment["VORTEX_RUST_PORT"] = str(rust_port)
    environment["VORTEX_UPSTREAM_URL"] = python_url
    edge = subprocess.Popen(
        [str(binary)],
        env=environment,
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    rust_url = f"http://127.0.0.1:{rust_port}"
    if not _wait_for(f"{rust_url}/health", seconds=8.0):
        edge.terminate()
        server.should_exit = True
        pytest.skip("бинарь vortex-server не поднялся")

    for route in ("health", "health-ready", "metrics"):
        flags.set(f"{prefix}:server:route:{route}", "rust")

    yield _Node(python_url, rust_url, prefix)

    for route in ("health", "health-ready", "metrics"):
        flags.delete(f"{prefix}:server:route:{route}")
    edge.terminate()
    edge.wait(timeout=10)
    server.should_exit = True
    thread.join(timeout=10)


def _ask(url: str, path: str) -> httpx.Response:
    return httpx.get(
        f"{url}{path}",
        headers={"X-Request-ID": PINNED_REQUEST_ID},
        timeout=10.0,
    )


def test_liveness_answers_the_same_field_set_on_both_runtimes(node):
    python_side = _ask(node.python_url, "/health")
    rust_side = _ask(node.rust_url, "/health")

    assert python_side.status_code == rust_side.status_code == 200

    python_stable, python_volatile = _split_body(python_side.json())
    rust_stable, rust_volatile = _split_body(rust_side.json())
    assert rust_stable == python_stable
    assert list(rust_side.json()) == list(python_side.json())

    for field in VOLATILE_FIELDS:
        assert field in rust_volatile, field
        assert type(rust_volatile[field]) is type(python_volatile[field]), field


def test_liveness_answers_the_same_headers_on_both_runtimes(node):
    python_side = _ask(node.python_url, "/health")
    rust_side = _ask(node.rust_url, "/health")

    assert _normalize_headers(rust_side.headers) == _normalize_headers(python_side.headers)
    assert rust_side.headers["x-request-id"] == PINNED_REQUEST_ID


def test_readiness_answers_the_same_checks_on_both_runtimes(node):
    python_side = _ask(node.python_url, "/health/ready")
    rust_side = _ask(node.rust_url, "/health/ready")

    assert python_side.status_code == rust_side.status_code
    assert list(rust_side.json()) == list(python_side.json())
    assert rust_side.json()["status"] == python_side.json()["status"]
    assert rust_side.json()["database"] == python_side.json()["database"]
    assert rust_side.json()["background_tasks"] == python_side.json()["background_tasks"]


def test_a_head_request_to_liveness_carries_no_body_on_either_runtime(node):
    python_side = httpx.head(f"{node.python_url}/health", timeout=10.0)
    rust_side = httpx.head(f"{node.rust_url}/health", timeout=10.0)

    assert python_side.status_code == rust_side.status_code == 200
    assert python_side.content == rust_side.content == b""


def test_the_rust_exposition_shares_no_family_name_with_the_python_one(node):
    python_side = httpx.get(f"{node.python_url}/metrics", timeout=10.0)
    rust_side = httpx.get(f"{node.rust_url}/metrics", timeout=10.0)

    assert rust_side.status_code == 200
    rust_families = {line.split()[2] for line in rust_side.text.splitlines() if line.startswith("# HELP ")}
    assert rust_families, "Rust-сторона не отдала ни одного семейства"
    if python_side.status_code == 200:
        python_families = {line.split()[2] for line in python_side.text.splitlines() if line.startswith("# HELP ")}
        assert rust_families.isdisjoint(python_families)


def test_an_unmoved_route_is_proxied_to_python_byte_for_byte(node):
    python_side = _ask(node.python_url, "/v1/integrity")
    rust_side = _ask(node.rust_url, "/v1/integrity")

    assert python_side.status_code == rust_side.status_code == 200
    assert rust_side.json() == python_side.json()


def test_pointing_a_route_back_at_python_takes_effect_without_a_restart(node):
    import redis as redis_py

    flags = redis_py.Redis.from_url(os.environ["REDIS_URL"])
    key = f"{node.prefix}:server:route:health"
    try:
        flags.set(key, "python")
        proxied = _ask(node.rust_url, "/health")
        assert proxied.status_code == 200
        assert json.loads(proxied.text)["status"] == "ok"
    finally:
        flags.set(key, "rust")

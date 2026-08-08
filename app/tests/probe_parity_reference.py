"""Независимая Python-реализация правил проб цензуры и мониторинга задержек.

Не продуктовый код и не снимок прошлой реализации: это вторая, независимо
написанная реализация правил, против которых сверяется `vortex-transport`.

Каталог проб. Десять транспортов, порядок таблицы задаёт приоритет выбора.
Вид пробы определяет адрес и то, какой ответ считается достижением цели:

    Health       GET /health                      200, 401, 403
    WebSocket    GET /ws/chat/0                   101, 200, 401, 403, 426
    Sse          GET /api/transport/sse/stream    200, 401, 403
                 (с заголовком Accept: text/event-stream)
    Token        GET /api/transport/probe/<токен> только 200

Токен транспорта — первые 12 шестнадцатеричных знаков SHA-256 его имени,
то есть первые 6 байт дайджеста. Секретом он не является: имена лежат в
открытом репозитории, а значит токен вычисляет кто угодно; он лишь делает
probe-роут неотличимым от несуществующего пути для всех остальных запросов.

Выбор транспорта. Первый по порядку таблицы, чья проба удалась; если не
удалась ни одна — не выбран никакой.

Задержки. Замер `> 0` — ответ, всё остальное (включая ровно 0) — отказ.
Три отказа подряд означают блокировку; ответ, который больше среднего по
предыдущим ответам втрое, означает деградацию, но только когда замеров
больше пяти. Блокировка читается раньше деградации. Округление —
от нуля (0.5 → 1), а не к чётному, как у встроенного round().
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

TOKEN_HEX_LEN = 12

HEALTH_PATH = "/health"
WEBSOCKET_PATH = "/ws/chat/0"
SSE_PATH = "/api/transport/sse/stream"
TOKEN_PATH_PREFIX = "/api/transport/probe/"  # noqa: S105
EVENT_STREAM = "text/event-stream"

HEALTH = "health"
WEBSOCKET = "websocket"
SSE = "sse"
TOKEN = "token"  # noqa: S105

ACCEPTED = {
    HEALTH: [200, 401, 403],
    WEBSOCKET: [101, 200, 401, 403, 426],
    SSE: [200, 401, 403],
    TOKEN: [200],
}

CATALOGUE = [
    ("reality", 1, 8.0, TOKEN),
    ("direct_https", 2, 5.0, HEALTH),
    ("websocket", 3, 5.0, WEBSOCKET),
    ("sse", 4, 8.0, SSE),
    ("trojan", 5, 10.0, TOKEN),
    ("shadowtls", 6, 10.0, TOKEN),
    ("cdn_relay", 7, 10.0, TOKEN),
    ("meek_cdn", 8, 15.0, TOKEN),
    ("doh_tunnel", 9, 15.0, TOKEN),
    ("tor", 10, 30.0, TOKEN),
]

FAILURES_TO_BLOCK = 3
SAMPLES_BEFORE_DEGRADATION = 5
DEGRADATION_FACTOR = 3.0

PROBE_INTERVAL = 60.0
JITTER_LOW = 0.5
JITTER_HIGH = 1.8

SW_VERSION = "4.0"
SW_FALLBACK_TRANSPORT = "direct"
SW_CACHE_TTL = 3600
PAD_BUCKETS = [128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
PAD_PROMOTE_PROBABILITY = 0.15
PAD_TILE_STEP = 8192
RETRY_MAX_ATTEMPTS = 3
RETRY_BACKOFF_BASE = 1000
RETRY_BACKOFF_MAX = 30000


def token_of(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:TOKEN_HEX_LEN]


def _entry(name: str) -> Optional[tuple]:
    for known in CATALOGUE:
        if known[0] == name:
            return known
    return None


def path_of(name: str, kind: str) -> str:
    if kind == HEALTH:
        return HEALTH_PATH
    if kind == WEBSOCKET:
        return WEBSOCKET_PATH
    if kind == SSE:
        return SSE_PATH
    return TOKEN_PATH_PREFIX + token_of(name)


def plan_of(name: str) -> Optional[dict]:
    entry = _entry(name)
    if entry is None:
        return None
    _, priority, timeout, kind = entry
    return {
        "priority": priority,
        "timeout": timeout,
        "path": path_of(name, kind),
        "accepted": list(ACCEPTED[kind]),
        "accept_header": EVENT_STREAM if kind == SSE else None,
    }


def serves(token: str) -> Optional[str]:
    if len(token) != TOKEN_HEX_LEN or not all(c in "0123456789abcdefABCDEF" for c in token):
        return None
    wanted = token.lower()
    for name, _, _, _ in CATALOGUE:
        if token_of(name) == wanted:
            return name
    return None


def best_transport(working: list[str]) -> Optional[str]:
    for name, _, _, _ in CATALOGUE:
        if name in working:
            return name
    return None


def _answers(samples: list[float]) -> list[float]:
    return [value for value in samples if value > 0]


def is_blocked(samples: list[float]) -> bool:
    if len(samples) < FAILURES_TO_BLOCK:
        return False
    return all(value <= 0 for value in samples[-FAILURES_TO_BLOCK:])


def is_degraded(samples: list[float]) -> bool:
    if not samples or len(samples) <= SAMPLES_BEFORE_DEGRADATION:
        return False
    latest = samples[-1]
    if latest <= 0:
        return False
    earlier = _answers(samples[:-1])
    if not earlier:
        return False
    average = sum(earlier) / len(earlier)
    return average > 0 and latest > average * DEGRADATION_FACTOR


def verdict(samples: list[float]) -> str:
    if is_blocked(samples):
        return "blocked"
    if is_degraded(samples):
        return "degraded"
    return "fine"


def _round_away_from_zero(value: float) -> int:
    if value < 0:
        return -math.floor(-value + 0.5)
    return math.floor(value + 0.5)


def stats(samples: list[float]) -> dict:
    answers = _answers(samples)
    return {
        "current": float(samples[-1]) if samples else -1.0,
        "avg": _round_away_from_zero(sum(answers) / len(answers)) if answers else -1,
        "min": _round_away_from_zero(min(answers)) if answers else -1,
        "max": _round_away_from_zero(max(answers)) if answers else -1,
        "failures": sum(1 for value in samples if value <= 0),
        "total_probes": len(samples),
    }


def pad_target(length: int) -> int:
    for bucket in PAD_BUCKETS:
        if bucket >= length:
            return bucket
    return -(-length // PAD_TILE_STEP) * PAD_TILE_STEP


def sw_profile(transports: list[str], cdn_url: str, meek_url: str) -> dict:
    return {
        "version": SW_VERSION,
        "transports": list(transports),
        "primary_transport": transports[0] if transports else SW_FALLBACK_TRANSPORT,
        "cdn_relay_url": cdn_url,
        "meek_url": meek_url,
        "cache_ttl": SW_CACHE_TTL,
        "probe_interval": _round_away_from_zero(PROBE_INTERVAL),
        "probe_interval_min": _round_away_from_zero(PROBE_INTERVAL * JITTER_LOW),
        "probe_interval_max": _round_away_from_zero(PROBE_INTERVAL * JITTER_HIGH),
        "padding": {
            "enabled": True,
            "buckets": list(PAD_BUCKETS),
            "promote_probability": PAD_PROMOTE_PROBABILITY,
            "tile_step": PAD_TILE_STEP,
        },
        "retry": {
            "max_attempts": RETRY_MAX_ATTEMPTS,
            "backoff_base": RETRY_BACKOFF_BASE,
            "backoff_max": RETRY_BACKOFF_MAX,
        },
    }


@dataclass(frozen=True)
class ParityFunction:
    name: str
    python: Callable[[dict], dict]
    cases: list[dict]


def _token_case(args: dict) -> dict:
    return {"token": token_of(args["name"]), "serves": serves(token_of(args["name"]))}


def _plan_case(args: dict) -> dict:
    return {"plan": plan_of(args["name"])}


def _serves_case(args: dict) -> dict:
    return {"serves": serves(args["token"])}


def _best_case(args: dict) -> dict:
    return {"best": best_transport(args["working"])}


def _verdict_case(args: dict) -> dict:
    return {"verdict": verdict(args["samples"])}


def _stats_case(args: dict) -> dict:
    return {"stats": stats(args["samples"])}


def _sw_profile_case(args: dict) -> dict:
    return {"profile": sw_profile(args["transports"], args["cdn_url"], args["meek_url"])}


def _pad_target_case(args: dict) -> dict:
    return {"target": pad_target(args["length"])}


FUNCTIONS = [
    ParityFunction(
        name="probe_token",
        python=_token_case,
        cases=[{"name": name} for name, _, _, _ in CATALOGUE],
    ),
    ParityFunction(
        name="probe_plan",
        python=_plan_case,
        cases=[{"name": name} for name, _, _, _ in CATALOGUE]
        + [{"name": "vmess"}, {"name": "Reality"}, {"name": ""}],
    ),
    ParityFunction(
        name="probe_serves",
        python=_serves_case,
        cases=[
            {"token": token_of("reality")},
            {"token": token_of("tor")},
            {"token": token_of("reality").upper()},
            {"token": token_of("vmess")},
            {"token": "000000000000"},
            {"token": "d7ac1d220e6"},
            {"token": "d7ac1d220e6a0"},
            {"token": "0xd7ac1d220e"},
            {"token": "d7ac1d220e6g"},
            {"token": "d7ac_1d220e6"},
            {"token": " d7ac1d220e6a"},
            {"token": ""},
        ],
    ),
    ParityFunction(
        name="best_transport",
        python=_best_case,
        cases=[
            {"working": []},
            {"working": ["reality"]},
            {"working": ["tor"]},
            {"working": ["reality", "tor"]},
            {"working": ["tor", "sse"]},
            {"working": ["websocket", "doh_tunnel"]},
            {"working": ["meek_cdn", "cdn_relay", "trojan"]},
            {"working": [name for name, _, _, _ in CATALOGUE]},
            {"working": ["direct_https", "reality"]},
            {"working": ["vmess"]},
        ],
    ),
    ParityFunction(
        name="latency_verdict",
        python=_verdict_case,
        cases=[
            {"samples": []},
            {"samples": [10.0]},
            {"samples": [-1.0, -1.0]},
            {"samples": [-1.0, -1.0, -1.0]},
            {"samples": [10.0, -1.0, -1.0, -1.0]},
            {"samples": [-1.0, -1.0, -1.0, 10.0]},
            {"samples": [0.0, 0.0, 0.0]},
            {"samples": [10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 100.0]},
            {"samples": [10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 30.0]},
            {"samples": [10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 30.1]},
            {"samples": [10.0, 10.0, 100.0]},
            {"samples": [10.0, 10.0, 10.0, 10.0, 10.0, -1.0, -1.0, -1.0]},
            {"samples": [-1.0, -1.0, -1.0, -1.0, -1.0, -1.0, 100.0]},
            {"samples": [5.0, 5.0, 5.0, 5.0, 5.0, 5.0, -1.0]},
        ],
    ),
    ParityFunction(
        name="latency_stats",
        python=_stats_case,
        cases=[
            {"samples": []},
            {"samples": [10.0]},
            {"samples": [10.0, -1.0, 30.0]},
            {"samples": [-1.0, -1.0]},
            {"samples": [0.0]},
            {"samples": [0.0, 10.0]},
            {"samples": [2.0, 3.0]},
            {"samples": [1.0, 2.0]},
            {"samples": [2.5, 2.5]},
            {"samples": [10.4, 10.6]},
            {"samples": [1000.0, 2000.0, 3000.0, -1.0, 4000.0]},
        ],
    ),
    ParityFunction(
        name="sw_profile",
        python=_sw_profile_case,
        cases=[
            {"transports": [], "cdn_url": "", "meek_url": ""},
            {
                "transports": ["websocket", "sse", "cdn_relay", "meek", "doh"],
                "cdn_url": "",
                "meek_url": "",
            },
            {
                "transports": ["reality"],
                "cdn_url": "https://cdn.example.com",
                "meek_url": "https://meek.example.com",
            },
            {"transports": ["vmess", "tor"], "cdn_url": "", "meek_url": ""},
        ],
    ),
    ParityFunction(
        name="sw_pad_target",
        python=_pad_target_case,
        cases=[
            {"length": 0},
            {"length": 1},
            {"length": 127},
            {"length": 128},
            {"length": 129},
            {"length": 65535},
            {"length": 65536},
            {"length": 65537},
            {"length": 73728},
            {"length": 73729},
            {"length": 200000},
        ],
    ),
]

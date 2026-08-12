#!/usr/bin/env python3
"""Генератор замороженных векторов шага 3.10 (механизмы Level 3).

Векторы снимаются со второй, независимой Python-реализации
(`app/tests/stealth3_parity_reference.py`), а не с Rust: иначе файл фиксировал
бы то, что Rust делает сегодня, а не то, о чём договорились две стороны.

    python scripts/gen_stealth3_parity_vectors.py
"""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.tests import stealth3_parity_reference as ref  # noqa: E402

OUT = ROOT / "app" / "tests" / "vectors" / "stealth3_parity.json"

HEADER_CASES = [
    [("Accept-Language", "ru"), ("User-Agent", "Chrome"), ("Host", "example.org"), ("Accept", "*/*")],
    [("X-Request-Id", "1"), ("Accept", "*/*"), ("X-Trace", "2"), ("Host", "example.org")],
    [("Accept", "text/html"), ("accept", "*/*")],
    [("uSeR-aGeNt", "Chrome")],
    [],
    [("Cookie", "a=1"), ("Origin", "https://x"), ("Referer", "https://y"), ("Host", "h")],
]

DGA_CASES = [
    ("vortex-mesh-2026", "2026-08-08", 5),
    ("vortex-mesh-2026", "2026-08-09", 5),
    ("another-seed", "2026-08-08", 3),
    ("", "1970-01-01", 2),
    ("vortex-mesh-2026", "2100-12-31", 4),
]

ENTROPY_CASES = [
    b"",
    b"a",
    b"hello world",
    bytes(range(256)),
    b"\x00" * 65535,
    b"\xab" * 65536,
    b"\x11" * (65535 * 2 + 5),
]

DOH_CASES = [
    ("cdn-sync.net", b"", 0),
    ("cdn-sync.net", b"hello", 42),
    ("cdn-sync.net", bytes(range(256)), 7),
    ("cdn-sync.net", b"x" * 500, 1),
    ("a.io", b"probe payload", 9),
    ("tunnel.example.org", b"y" * 300, 3),
]

DNS_QUERY_CASES = [
    ("example.org", 1),
    ("a.b.c.d", 1),
    ("cdn-sync.net", 16),
    ("", 1),
    ("a..b", 1),
    ("россия.рф", 1),
]

PROBE_CASES = [
    (
        "browser on an api route",
        "203.0.113.7",
        "GET",
        "/api/chats",
        {
            "Host": "x",
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Accept-Language": "ru",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Dest": "empty",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Cookie": "session=1",
        },
    ),
    (
        "httpx client on an ordinary route",
        "203.0.113.7",
        "GET",
        "/api/chats",
        {
            "Host": "example.org",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "User-Agent": "python-httpx/0.28.1",
        },
    ),
    (
        "remote node probing health",
        "203.0.113.7",
        "GET",
        "/health",
        {"Host": "example.org", "Accept": "*/*", "User-Agent": "python-httpx/0.28.1"},
    ),
    (
        "federation handshake",
        "203.0.113.7",
        "POST",
        "/api/federation/handshake",
        {"Host": "example.org", "User-Agent": "python-httpx/0.28.1"},
    ),
    ("scanner", "203.0.113.7", "GET", "/api/chats", {"User-Agent": "sqlmap/1.7.11#stable (https://sqlmap.org)"}),
    ("client on this machine", "127.0.0.1", "GET", "/api/chats", {}),
    ("client on the local network", "192.168.1.5", "GET", "/api/chats", {}),
    ("address the old prefix let through", "172.2.3.4", "GET", "/api/chats", {}),
    ("address inside the private range", "172.20.1.1", "GET", "/api/chats", {}),
    (
        "telegram data centre",
        "149.154.167.99",
        "GET",
        "/api/chats",
        {
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Accept-Language": "ru",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Dest": "empty",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Cookie": "a=1",
        },
    ),
    (
        "suspected network with a browser request",
        "109.124.1.1",
        "GET",
        "/api/chats",
        {
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Accept-Language": "ru",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Dest": "empty",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Cookie": "a=1",
        },
    ),
    ("front page without a cookie", "203.0.113.7", "GET", "/", {"User-Agent": "Mozilla/5.0 Chrome/120 long enough"}),
    (
        "script fetched by something that does not accept scripts",
        "203.0.113.7",
        "GET",
        "/static/js/app.js",
        {
            "Accept": "text/html",
            "Accept-Encoding": "gzip",
            "Accept-Language": "ru",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Dest": "script",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0",
            "Cookie": "a=1",
        },
    ),
    ("peer with no readable address", "", "GET", "/api/chats", {}),
]


def build() -> dict:
    vectors: dict[str, list] = {}

    vectors["header_order"] = [
        {"fields": fields, "arranged": ref.arrange_headers(fields)} for fields in HEADER_CASES
    ]

    vectors["dga_domains"] = [
        {"seed": seed, "day": day, "count": count, "domains": ref.dga_domains(seed, day, count)}
        for seed, day, count in DGA_CASES
    ]

    vectors["entropy_envelope"] = [
        {"payload": payload.hex(), "envelope": ref.entropy_wrap(payload).hex()} for payload in ENTROPY_CASES
    ]

    vectors["entropy_refusal"] = [
        {"envelope": bad.hex(), "refused": ref.entropy_unwrap(bad) is None}
        for bad in [
            b"",
            b"plain text that is long enough to measure",
            bytes([0x1F, 0x8B]),
            ref.entropy_wrap(b"hello world")[:-1],
            ref.entropy_wrap(b"hello world")[:10] + b"\x00" * 20,
        ]
    ]

    vectors["doh_names"] = [
        {
            "suffix": suffix,
            "payload": payload.hex(),
            "message": message,
            "names": ref.doh_encode(suffix, payload, message),
            "payload_per_query": ref.doh_payload_size(suffix),
        }
        for suffix, payload, message in DOH_CASES
    ]

    vectors["dns_query"] = [
        {"host": host, "kind": kind, "wire": (ref.dns_query(host, kind) or b"").hex(), "ok": ref.dns_query(host, kind) is not None}
        for host, kind in DNS_QUERY_CASES
    ]

    replies = []
    for records in [
        [(1, 1, bytes([93, 184, 216, 34]))],
        [(1, 1, bytes([10, 0, 0, 1])), (1, 1, bytes([10, 0, 0, 2]))],
        [(5, 1, b"\x03www\x00"), (16, 1, b"\x04text"), (1, 1, bytes([8, 8, 8, 8]))],
        [(1, 3, bytes([10, 0, 0, 1]))],
        [(1, 1, bytes([10, 0, 0]))],
        [],
    ]:
        wire = bytearray(b"\x00\x00\x81\x80\x00\x01")
        wire += len(records).to_bytes(2, "big") + b"\x00\x00\x00\x00"
        wire += b"\x07example\x03org\x00\x00\x01\x00\x01"
        for kind, klass, data in records:
            wire += b"\xc0\x0c" + kind.to_bytes(2, "big") + klass.to_bytes(2, "big")
            wire += b"\x00\x00\x01\x2c" + len(data).to_bytes(2, "big") + data
        replies.append({"wire": bytes(wire).hex(), "addresses": ref.dns_addresses(bytes(wire))})
    vectors["dns_answer"] = replies

    vectors["probe_verdict"] = [
        {
            "name": name,
            "peer": peer,
            "method": method,
            "path": path,
            "headers": headers,
            **ref.probe_verdict(peer, method, path, headers),
        }
        for name, peer, method, path, headers in PROBE_CASES
    ]

    return vectors


def main() -> None:
    vectors = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(vectors, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    total = sum(len(cases) for cases in vectors.values())
    print(f"{OUT}: {len(vectors)} функций, {total} векторов")


if __name__ == "__main__":
    main()

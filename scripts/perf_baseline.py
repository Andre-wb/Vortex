#!/usr/bin/env python3
"""Снятие и сравнение системного baseline перед переносом модулей в Rust.

`criterion` меряет функцию, этот скрипт меряет систему: латентность под
нагрузкой, пропускную способность и RSS живого процесса.

Снять эталон до переноса:
    python scripts/perf_baseline.py record --url http://127.0.0.1:9000 \\
        --out perf/baseline.json --label "python-before"

Снять после и сравнить:
    python scripts/perf_baseline.py record --url http://127.0.0.1:9000 \\
        --out perf/after.json --label "rust-waf"
    python scripts/perf_baseline.py compare perf/baseline.json perf/after.json

`compare` возвращает ненулевой код, если нарушен любой порог приёмки, —
годится как гейт в CI или в чек-листе релиза.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field

import httpx

DEFAULT_ENDPOINTS = ("/health", "/health/ready", "/metrics")

P99_TOLERANCE = 0.10
P95_TOLERANCE = 0.10
THROUGHPUT_TOLERANCE = 0.10
RSS_TOLERANCE = 0.20


@dataclass
class EndpointResult:
    path: str
    requests: int
    errors: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    throughput_rps: float


@dataclass
class Baseline:
    label: str
    recorded_at: int
    url: str
    concurrency: int
    rss_mb: float
    endpoints: list[EndpointResult] = field(default_factory=list)


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(int(len(ordered) * fraction), len(ordered) - 1)
    return ordered[index]


def _server_rss_mb(pid: int | None) -> float:
    if pid is None:
        return 0.0
    try:
        import resource
        if pid == os.getpid():
            usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            return usage / (1024 * 1024) if sys.platform == "darwin" else usage / 1024
    except ImportError:
        pass
    try:
        import subprocess
        out = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(pid)],
            capture_output=True, text=True, check=True,
        )
        return int(out.stdout.strip()) / 1024
    except Exception:
        return 0.0


def _hammer(url: str, path: str, requests: int, concurrency: int) -> EndpointResult:
    latencies: list[float] = []
    errors = 0

    def one_request(client: httpx.Client) -> float | None:
        start = time.perf_counter()
        try:
            response = client.get(path)
        except httpx.HTTPError:
            return None
        elapsed = (time.perf_counter() - start) * 1000
        return elapsed if response.status_code < 500 else None

    started = time.perf_counter()
    with httpx.Client(base_url=url, timeout=10.0) as client, ThreadPoolExecutor(max_workers=concurrency) as pool:
        for result in pool.map(lambda _: one_request(client), range(requests)):
            if result is None:
                errors += 1
            else:
                latencies.append(result)
    wall = time.perf_counter() - started

    return EndpointResult(
        path=path,
        requests=requests,
        errors=errors,
        p50_ms=round(statistics.median(latencies), 3) if latencies else 0.0,
        p95_ms=round(_percentile(latencies, 0.95), 3),
        p99_ms=round(_percentile(latencies, 0.99), 3),
        throughput_rps=round(requests / wall, 1) if wall > 0 else 0.0,
    )


def record(args: argparse.Namespace) -> int:
    endpoints = args.endpoint or list(DEFAULT_ENDPOINTS)
    results = [
        _hammer(args.url, path, args.requests, args.concurrency) for path in endpoints
    ]
    baseline = Baseline(
        label=args.label,
        recorded_at=int(time.time()),
        url=args.url,
        concurrency=args.concurrency,
        rss_mb=round(_server_rss_mb(args.pid), 1),
        endpoints=results,
    )

    payload = asdict(baseline)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"записано: {args.out}")

    for result in results:
        print(
            f"{result.path:<20} p50={result.p50_ms:>8.3f}ms  p95={result.p95_ms:>8.3f}ms  "
            f"p99={result.p99_ms:>8.3f}ms  {result.throughput_rps:>8.1f} rps  "
            f"ошибок={result.errors}"
        )
    if baseline.rss_mb:
        print(f"RSS сервера: {baseline.rss_mb} МБ")
    return 0


def _regression(before: float, after: float, tolerance: float) -> tuple[bool, float]:
    if before <= 0:
        return False, 0.0
    delta = (after - before) / before
    return delta > tolerance, delta


def compare(args: argparse.Namespace) -> int:
    with open(args.before, encoding="utf-8") as fh:
        before = json.load(fh)
    with open(args.after, encoding="utf-8") as fh:
        after = json.load(fh)

    by_path = {item["path"]: item for item in after["endpoints"]}
    violations: list[str] = []

    print(f"{before['label']} → {after['label']}\n")
    for item in before["endpoints"]:
        path = item["path"]
        current = by_path.get(path)
        if current is None:
            violations.append(f"{path}: нет данных в {args.after}")
            continue

        for metric, tolerance in (("p95_ms", P95_TOLERANCE), ("p99_ms", P99_TOLERANCE)):
            bad, delta = _regression(item[metric], current[metric], tolerance)
            marker = "РЕГРЕССИЯ" if bad else "ok"
            print(
                f"{path:<20} {metric:<7} {item[metric]:>8.3f} → {current[metric]:>8.3f} "
                f"({delta:+.1%}) {marker}"
            )
            if bad:
                violations.append(
                    f"{path}: {metric} вырос на {delta:.1%} (порог {tolerance:.0%})"
                )

        bad, delta = _regression(
            current["throughput_rps"], item["throughput_rps"], THROUGHPUT_TOLERANCE
        )
        print(
            f"{path:<20} {'rps':<7} {item['throughput_rps']:>8.1f} → "
            f"{current['throughput_rps']:>8.1f} ({-delta:+.1%}) "
            f"{'РЕГРЕССИЯ' if bad else 'ok'}"
        )
        if bad:
            violations.append(
                f"{path}: пропускная способность упала на {delta:.1%} "
                f"(порог {THROUGHPUT_TOLERANCE:.0%})"
            )

    bad, delta = _regression(before["rss_mb"], after["rss_mb"], RSS_TOLERANCE)
    if before["rss_mb"]:
        print(
            f"\n{'RSS, МБ':<20} {before['rss_mb']:>8.1f} → {after['rss_mb']:>8.1f} "
            f"({delta:+.1%}) {'РЕГРЕССИЯ' if bad else 'ok'}"
        )
        if bad:
            violations.append(f"RSS вырос на {delta:.1%} (порог {RSS_TOLERANCE:.0%})")

    if violations:
        print("\nПороги приёмки нарушены:")
        for line in violations:
            print(f"  - {line}")
        return 1

    print("\nПороги приёмки соблюдены.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    rec = sub.add_parser("record", help="снять замер с живого сервера")
    rec.add_argument("--url", default="http://127.0.0.1:9000")
    rec.add_argument("--endpoint", action="append", help="можно повторять")
    rec.add_argument("--requests", type=int, default=500)
    rec.add_argument("--concurrency", type=int, default=16)
    rec.add_argument("--pid", type=int, help="pid сервера для замера RSS")
    rec.add_argument("--label", default="unlabeled")
    rec.add_argument("--out")
    rec.set_defaults(func=record)

    cmp_ = sub.add_parser("compare", help="сравнить два замера с порогами приёмки")
    cmp_.add_argument("before")
    cmp_.add_argument("after")
    cmp_.set_defaults(func=compare)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

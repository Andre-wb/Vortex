"""Кросс-языковые golden-тесты проб цензуры: Python и Rust решают одинаково.

Векторы: `app/tests/vectors/probe_parity.json` (генератор
`scripts/gen_probe_parity_vectors.py`), вторая независимая реализация правил —
`app/tests/probe_parity_reference.py`.

Отказ — такая же часть контракта, как и ответ: имя вне каталога не получает
плана, токен вне каталога не называет транспорта, а прогон, где не ответил
никто, не выбирает ничего.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.tests import probe_parity_reference as reference

VECTORS_PATH = Path(__file__).parent / "vectors" / "probe_parity.json"

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

    def test_refusals_are_frozen_too(self):
        vectors = _vectors()
        assert any(v["expected"]["plan"] is None for v in vectors["probe_plan"])
        assert any(v["expected"]["serves"] is None for v in vectors["probe_serves"])
        assert any(v["expected"]["best"] is None for v in vectors["best_transport"])


@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_python_matches_vector(fn, vector):
    assert fn.python(vector["args"]) == vector["expected"]


def _probe():
    return _rust.CensorshipProbe()


def _rust_probe_token(args: dict) -> dict:
    probe = _probe()
    token = probe.token(args["name"])
    return {"token": token, "serves": probe.serves(token) if token else None}


def _rust_probe_plan(args: dict) -> dict:
    for target in _probe().plan():
        if target.name != args["name"]:
            continue
        return {
            "plan": {
                "priority": reference.plan_of(args["name"])["priority"],
                "timeout": target.timeout,
                "path": target.path,
                "accepted": list(target.accepted),
                "accept_header": target.accept_header,
            }
        }
    return {"plan": None}


def _rust_probe_serves(args: dict) -> dict:
    return {"serves": _probe().serves(args["token"])}


def _rust_best_transport(args: dict) -> dict:
    probe = _probe()
    for target in probe.plan():
        if target.name in args["working"]:
            probe.answered(target.name, target.accepted[0], 5)
        else:
            probe.timed_out(target.name)
    return {"best": probe.finish(100.0)}


def _monitor(samples: list[float]):
    monitor = _rust.LatencyMonitor()
    verdict = "fine"
    for tick, sample in enumerate(samples):
        verdict = monitor.record("t", sample, float(tick))
    return monitor, verdict


def _rust_latency_verdict(args: dict) -> dict:
    _, verdict = _monitor(args["samples"])
    return {"verdict": verdict}


def _rust_latency_stats(args: dict) -> dict:
    monitor, _ = _monitor(args["samples"])
    return {"stats": monitor.stats_of("t")}


def _rust_sw_profile(args: dict) -> dict:
    profile = _rust.ServiceWorkerProfile()
    return {"profile": profile.build(args["transports"], args["cdn_url"], args["meek_url"])}


def _rust_pad_target(args: dict) -> dict:
    return {"target": _rust.ServiceWorkerProfile().target_for(args["length"])}


RUST_IMPLEMENTATIONS = {
    "sw_profile": _rust_sw_profile,
    "sw_pad_target": _rust_pad_target,
    "probe_token": _rust_probe_token,
    "probe_plan": _rust_probe_plan,
    "probe_serves": _rust_probe_serves,
    "best_transport": _rust_best_transport,
    "latency_verdict": _rust_latency_verdict,
    "latency_stats": _rust_latency_stats,
}


@requires_rust
@pytest.mark.parametrize("fn,vector", ALL_CASES)
def test_rust_matches_vector(fn, vector):
    assert RUST_IMPLEMENTATIONS[fn.name](vector["args"]) == vector["expected"]


@requires_rust
class TestCatalogueAgreesAcrossRuntimes:
    def test_both_runtimes_know_the_same_transports(self):
        assert list(_probe().transports) == [name for name, _, _, _ in reference.CATALOGUE]

    def test_the_plan_is_read_in_the_order_the_catalogue_is_written(self):
        assert [t.name for t in _probe().plan()] == [name for name, _, _, _ in reference.CATALOGUE]

    def test_a_token_probe_asks_for_the_path_its_token_names(self):
        for target in _probe().plan():
            if not target.path.startswith(reference.TOKEN_PATH_PREFIX):
                continue
            assert target.path == reference.TOKEN_PATH_PREFIX + reference.token_of(target.name)

    def test_no_probe_reads_a_missing_route_as_a_working_transport(self):
        for target in _probe().plan():
            assert 404 not in target.accepted
            assert 501 not in target.accepted


@requires_rust
class TestReprobeSchedule:
    def test_a_probe_that_never_ran_is_due_at_once(self):
        assert _probe().due(0.0)

    def test_a_finished_run_is_not_due_again_at_once(self):
        probe = _probe()
        probe.finish(1000.0)
        assert not probe.due(1000.0)
        assert probe.due(1000.0 + probe.interval + 1.0)

    def test_the_wait_is_never_the_same_twice(self):
        drawn = {_probe().interval for _ in range(200)}
        assert len(drawn) > 190

    def test_the_wait_stays_inside_the_bounds_of_the_base_interval(self):
        for _ in range(500):
            probe = _rust.CensorshipProbe(300.0)
            assert 150.0 <= probe.interval <= 600.0


@requires_rust
class TestAlertsAreNotRepeatedEveryProbe:
    def test_a_transport_that_stays_down_is_reported_once(self):
        monitor = _rust.LatencyMonitor()
        for tick in range(10):
            monitor.record("tor", -1.0, float(tick))
        assert len(monitor.alerts(50)) == 1

    def test_a_transport_that_recovers_and_falls_again_is_reported_twice(self):
        monitor = _rust.LatencyMonitor()
        for tick in range(3):
            monitor.record("tor", -1.0, float(tick))
        monitor.record("tor", 20.0, 4.0)
        for tick in range(5, 8):
            monitor.record("tor", -1.0, float(tick))
        assert len(monitor.alerts(50)) == 2

"""Метрики WAF: имена приходят из Rust, значения — из живого движка."""

from __future__ import annotations

import pytest
import vortex_waf

from app.security.waf import metrics as waf_metrics

prometheus_client = pytest.importorskip("prometheus_client")


@pytest.fixture
def registry():
    return prometheus_client.CollectorRegistry()


class _FakeEngine:
    def __init__(self, stats):
        self._stats = stats

    def get_stats(self):
        return self._stats


def _sample_stats(**overrides):
    stats = {
        "total_requests": 12,
        "blocked_requests": 3,
        "block_rate": 25.0,
        "rules_triggered": {"SQLI-001": 2, "XSS-004": 1},
        "ip_blocks": 5,
        "blocked_ips_count": 2,
        "active_rules": 3,
        "rules_loaded": 41,
    }
    stats.update(overrides)
    return stats


def _samples(engine):
    """Имя сэмпла → сэмплы. Именно эти имена попадают в выдачу `/metrics`."""
    out: dict[str, list] = {}
    for family in waf_metrics.WafStatsCollector(lambda: engine).collect():
        for sample in family.samples:
            out.setdefault(sample.name, []).append(sample)
    return out


class TestMetricNamesComeFromRust:
    def test_python_uses_exactly_the_rust_names(self):
        rust = vortex_waf.METRIC_NAMES
        assert rust["counters"] == waf_metrics.COUNTERS
        assert rust["gauges"] == waf_metrics.GAUGES
        assert rust["rule_triggers"] == waf_metrics.RULE_TRIGGERS_TOTAL
        assert rust["rule_label"] == waf_metrics.RULE_LABEL

    def test_every_name_is_namespaced(self):
        for name in waf_metrics.all_metric_names():
            assert name.startswith("vortex_waf_")

    def test_counters_and_gauges_do_not_overlap(self):
        assert not set(waf_metrics.COUNTERS) & set(waf_metrics.GAUGES)

    def test_snapshot_keys_exist_in_a_real_engine(self):
        stats = vortex_waf.WafEngine({}).get_stats()
        for key in list(waf_metrics.COUNTERS.values()) + list(waf_metrics.GAUGES.values()):
            assert key in stats


class TestCollector:
    def test_exports_counter_and_gauge_values(self):
        samples = _samples(_FakeEngine(_sample_stats()))

        assert samples["vortex_waf_requests_total"][0].value == 12
        assert samples["vortex_waf_blocked_requests_total"][0].value == 3
        assert samples["vortex_waf_ip_blocks_total"][0].value == 5
        assert samples["vortex_waf_blocked_ips"][0].value == 2
        assert samples["vortex_waf_rules_loaded"][0].value == 41

    def test_rule_triggers_carry_the_rule_label(self):
        samples = _samples(_FakeEngine(_sample_stats()))
        by_rule = {s.labels["rule"]: s.value for s in samples["vortex_waf_rule_triggers_total"]}
        assert by_rule == {"SQLI-001": 2, "XSS-004": 1}

    def test_derived_values_are_not_exported(self):
        samples = _samples(_FakeEngine(_sample_stats()))
        assert not any("block_rate" in name for name in samples)
        assert not any("rules_active" in name for name in samples)

    def test_rules_loaded_reflects_the_real_catalog(self):
        stats = vortex_waf.WafEngine({}).get_stats()
        assert stats["rules_loaded"] > 0

    def test_missing_keys_fall_back_to_zero(self):
        samples = _samples(_FakeEngine({}))
        assert samples["vortex_waf_requests_total"][0].value == 0

    def test_engine_failure_never_breaks_the_scrape(self, registry):
        class _Broken:
            def get_stats(self):
                raise RuntimeError("движок недоступен")

        registry.register(waf_metrics.WafStatsCollector(_Broken))
        assert prometheus_client.generate_latest(registry) is not None


class TestRegistration:
    def test_register_is_idempotent(self, registry):
        engine = _FakeEngine(_sample_stats())
        try:
            assert waf_metrics.register_waf_metrics(lambda: engine, registry) is True
            assert waf_metrics.register_waf_metrics(lambda: engine, registry) is False
        finally:
            waf_metrics.unregister_waf_metrics(registry)

    def test_registered_collector_reaches_the_exposition(self, registry):
        engine = _FakeEngine(_sample_stats())
        try:
            waf_metrics.register_waf_metrics(lambda: engine, registry)
            exposition = prometheus_client.generate_latest(registry).decode("utf-8")
        finally:
            waf_metrics.unregister_waf_metrics(registry)

        for name in waf_metrics.all_metric_names():
            assert name in exposition
        assert 'vortex_waf_rule_triggers_total{rule="SQLI-001"} 2.0' in exposition


class TestLiveEndpoint:
    def test_metrics_endpoint_exposes_waf_families(self, client):
        response = client.get("/metrics")
        if response.status_code != 200:
            pytest.skip("эндпоинт /metrics закрыт в этом окружении")
        for name in waf_metrics.all_metric_names():
            if name == waf_metrics.RULE_TRIGGERS_TOTAL:
                continue
            assert name in response.text

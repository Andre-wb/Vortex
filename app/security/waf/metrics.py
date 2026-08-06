"""Экспорт статистики Rust-движка WAF в Prometheus.

Имена метрик и соответствие ключам снимка приходят из `vortex_waf.METRIC_NAMES`.
"""

from __future__ import annotations

import contextlib
import logging
import weakref

import vortex_waf as _rust

logger = logging.getLogger(__name__)

METRIC_NAMES: dict = getattr(_rust, "METRIC_NAMES", None)
if METRIC_NAMES is None:
    raise ImportError("vortex_waf собран без METRIC_NAMES. Пересоберите расширение:\n    make rust-build")

COUNTERS: dict[str, str] = METRIC_NAMES["counters"]
GAUGES: dict[str, str] = METRIC_NAMES["gauges"]
RULE_TRIGGERS_TOTAL: str = METRIC_NAMES["rule_triggers"]
RULE_LABEL: str = METRIC_NAMES["rule_label"]

_HELP = {
    "total_requests": "Запросов проанализировано WAF",
    "blocked_requests": "Запросов заблокировано WAF",
    "ip_blocks": "Блокировок по IP наложено всего",
    "blocked_ips_count": "IP-адресов заблокировано сейчас",
    "rules_loaded": "Правил загружено в движок",
}

_registered: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def all_metric_names() -> set[str]:
    """Полный набор имён, которые движок публикует в Prometheus."""
    return set(COUNTERS) | set(GAUGES) | {RULE_TRIGGERS_TOTAL}


def _families():
    from prometheus_client.metrics_core import CounterMetricFamily, GaugeMetricFamily

    counters = {name: CounterMetricFamily(name, _HELP.get(key, name)) for name, key in COUNTERS.items()}
    gauges = {name: GaugeMetricFamily(name, _HELP.get(key, name)) for name, key in GAUGES.items()}
    rules = CounterMetricFamily(RULE_TRIGGERS_TOTAL, "Срабатываний правил", labels=[RULE_LABEL])
    return counters, gauges, rules


class WafStatsCollector:
    """Снимок счётчиков движка на каждый скрейп.

    Ошибка Rust-стороны гасится: исключение из `collect()` оборвало бы всю
    выдачу `/metrics`.
    """

    def __init__(self, engine_provider):
        self._engine_provider = engine_provider

    def describe(self):
        counters, gauges, rules = _families()
        yield from counters.values()
        yield from gauges.values()
        yield rules

    def collect(self):
        try:
            stats = self._engine_provider().get_stats()
        except Exception as exc:
            logger.warning("WAF metrics: снимок статистики недоступен: %s", exc)
            return

        counters, gauges, rules = _families()

        for name, key in COUNTERS.items():
            counters[name].add_metric([], stats.get(key, 0))
        for name, key in GAUGES.items():
            gauges[name].add_metric([], stats.get(key, 0))
        for rule_id, count in (stats.get("rules_triggered") or {}).items():
            rules.add_metric([str(rule_id)], count)

        yield from counters.values()
        yield from gauges.values()
        yield rules


def _resolve_registry(registry):
    if registry is not None:
        return registry
    try:
        from prometheus_client import REGISTRY
    except ImportError:
        return None
    return REGISTRY


def register_waf_metrics(engine_provider, registry=None) -> bool:
    """Подключить коллектор к реестру Prometheus. Повторный вызов — no-op.

    Возвращает True, если коллектор зарегистрирован именно этим вызовом.
    """
    target = _resolve_registry(registry)
    if target is None or target in _registered:
        return False

    collector = WafStatsCollector(engine_provider)
    try:
        target.register(collector)
    except ValueError as exc:
        logger.warning("WAF metrics: коллектор уже зарегистрирован: %s", exc)
        return False

    _registered[target] = collector
    return True


def unregister_waf_metrics(registry=None) -> None:
    """Снять коллектор с реестра — нужно тестам, чтобы не течь между кейсами."""
    target = _resolve_registry(registry)
    collector = _registered.pop(target, None) if target is not None else None
    if collector is None:
        return
    with contextlib.suppress(KeyError):
        target.unregister(collector)

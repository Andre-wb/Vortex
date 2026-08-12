"""Паритет шага 3.10: Rust против независимой Python-реализации.

Проверяется двумя способами. Первый — замороженные векторы
(`vectors/stealth3_parity.json`), снятые с `stealth3_parity_reference.py`:
они ловят молчаливую смену формата. Второй — сверка на месте для границ,
которые вектором не заморозить (очень длинные полезные нагрузки, состояние
детектора между запросами).
"""

from __future__ import annotations

import json
import pathlib

import pytest

from app.tests import stealth3_parity_reference as ref

vortex_chat = pytest.importorskip("vortex_chat", reason="расширение vortex_chat не собрано")

VECTORS = json.loads((pathlib.Path(__file__).parent / "vectors" / "stealth3_parity.json").read_text("utf-8"))


def _detector():
    return vortex_chat.ProbeDetector()


class TestHeaderOrder:
    @pytest.mark.parametrize("case", VECTORS["header_order"])
    def test_the_order_matches_the_frozen_vector(self, case):
        fields = [tuple(field) for field in case["fields"]]
        expected = [tuple(field) for field in case["arranged"]]
        assert vortex_chat.header_order(fields) == expected

    def test_the_set_chrome_sends_is_already_ordered(self):
        fields = vortex_chat.chrome_headers("example.org", "/", "https://yandex.ru/", "a=1")
        assert vortex_chat.header_order(fields) == fields


class TestDomainGenerator:
    @pytest.mark.parametrize("case", VECTORS["dga_domains"])
    def test_the_domains_match_the_frozen_vector(self, case):
        generator = vortex_chat.DomainGenerator(case["seed"])
        assert generator.on(case["day"], case["count"]) == case["domains"]

    def test_both_runtimes_agree_on_days_nobody_froze(self):
        seed = "vortex-mesh-2026"
        generator = vortex_chat.DomainGenerator(seed)
        for day in ["2026-01-01", "2027-06-15", "2038-01-19", "1999-12-31"]:
            assert generator.on(day, 8) == ref.dga_domains(seed, day, 8)

    def test_the_current_domains_cover_today_and_tomorrow_in_utc(self):
        generator = vortex_chat.DomainGenerator("vortex-mesh-2026")
        midnight = 1_754_611_200
        assert generator.current(midnight, 3) == generator.current(midnight + 3600 * 11, 3)
        assert generator.current(midnight, 3)[:3] == ref.dga_domains("vortex-mesh-2026", "2025-08-08", 3)


class TestEntropyEnvelope:
    @pytest.mark.parametrize("case", VECTORS["entropy_envelope"])
    def test_the_envelope_matches_the_frozen_vector(self, case):
        payload = bytes.fromhex(case["payload"])
        assert bytes(vortex_chat.EntropyEnvelope.wrap(payload)).hex() == case["envelope"]

    @pytest.mark.parametrize("case", VECTORS["entropy_envelope"])
    def test_each_runtime_opens_what_the_other_sealed(self, case):
        payload = bytes.fromhex(case["payload"])
        sealed_by_rust = bytes(vortex_chat.EntropyEnvelope.wrap(payload))
        assert ref.entropy_unwrap(sealed_by_rust) == payload
        assert bytes(vortex_chat.EntropyEnvelope.unwrap(ref.entropy_wrap(payload))) == payload

    @pytest.mark.parametrize("case", VECTORS["entropy_refusal"])
    def test_what_one_runtime_refuses_the_other_refuses_too(self, case):
        envelope = bytes.fromhex(case["envelope"])
        assert case["refused"] is True
        assert vortex_chat.EntropyEnvelope.unwrap(envelope) is None

    def test_a_payload_too_large_to_freeze_still_round_trips(self):
        payload = bytes(range(256)) * 4096
        assert bytes(vortex_chat.EntropyEnvelope.unwrap(ref.entropy_wrap(payload))) == payload
        assert ref.entropy_unwrap(bytes(vortex_chat.EntropyEnvelope.wrap(payload))) == payload


class TestDohTunnel:
    @pytest.mark.parametrize("case", VECTORS["doh_names"])
    def test_the_names_match_the_frozen_vector(self, case):
        tunnel = vortex_chat.DohTunnel(case["suffix"])
        payload = bytes.fromhex(case["payload"])
        assert tunnel.encode(payload, case["message"]) == case["names"]
        assert tunnel.payload_per_query == case["payload_per_query"]

    @pytest.mark.parametrize("case", VECTORS["doh_names"])
    def test_each_runtime_reads_the_names_the_other_wrote(self, case):
        tunnel = vortex_chat.DohTunnel(case["suffix"])
        payload = bytes.fromhex(case["payload"])
        rebuilt = b""
        for position, name in enumerate(ref.doh_encode(case["suffix"], payload, case["message"])):
            message, total, index, piece = tunnel.decode(name)
            assert message == case["message"]
            assert index == position
            assert total == len(case["names"])
            rebuilt += bytes(piece)
        assert rebuilt == payload

        rebuilt = b""
        for name in tunnel.encode(payload, case["message"]):
            decoded = ref.doh_decode(case["suffix"], name)
            assert decoded is not None
            rebuilt += decoded[3]
        assert rebuilt == payload

    @pytest.mark.parametrize("case", VECTORS["doh_names"])
    def test_every_name_fits_what_dns_allows(self, case):
        for name in case["names"]:
            assert ref.wire_length(name) <= 255, name
            for label in name.split("."):
                assert 0 < len(label) <= 63

    def test_a_suffix_that_leaves_no_room_is_refused_by_both(self):
        huge = ".".join(["abcdefghij"] * 25)
        assert ref.doh_payload_size(huge) is None
        with pytest.raises(ValueError):
            vortex_chat.DohTunnel(huge)


class TestDnsWire:
    @pytest.mark.parametrize("case", VECTORS["dns_query"])
    def test_the_query_matches_the_frozen_vector(self, case):
        if not case["ok"]:
            with pytest.raises(ValueError):
                vortex_chat.dns_query(case["host"], case["kind"])
            return
        assert bytes(vortex_chat.dns_query(case["host"], case["kind"])).hex() == case["wire"]

    @pytest.mark.parametrize("case", VECTORS["dns_answer"])
    def test_the_addresses_match_the_frozen_vector(self, case):
        assert vortex_chat.dns_addresses(bytes.fromhex(case["wire"])) == case["addresses"]

    def test_a_reply_cut_at_any_point_never_invents_an_address(self):
        wire = bytes.fromhex(VECTORS["dns_answer"][1]["wire"])
        for cut in range(len(wire)):
            assert vortex_chat.dns_addresses(wire[:cut]) == ref.dns_addresses(wire[:cut])


class TestProbeDetector:
    @pytest.mark.parametrize("case", VECTORS["probe_verdict"])
    def test_the_verdict_matches_the_frozen_vector(self, case):
        headers = [(name, value) for name, value in case["headers"].items()]
        verdict, reason = _detector().inspect(case["peer"], case["method"], case["path"], headers, 1000.0)
        assert verdict == case["is_probe"], f"{case['name']}: {reason}"
        raised = reason.split("; ") if reason else []
        assert raised == case["signals"], case["name"]

    def test_a_remote_node_health_probe_is_never_answered_with_a_cover_page(self):
        import httpx

        headers = list(httpx.Client().build_request("GET", "https://x/health").headers.items())
        verdict, reason = _detector().inspect("203.0.113.7", "GET", "/health", headers, 1000.0)
        assert verdict is False, reason

    def test_the_replay_signal_needs_state_and_so_is_checked_here_and_not_frozen(self):
        detector = _detector()
        headers = [("user-agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0"), ("cookie", "a=1")]
        first, _ = detector.inspect("203.0.113.7", "GET", "/api/chats", headers, 1000.0)
        assert first is False
        _, reason = detector.inspect("203.0.113.7", "GET", "/api/chats", headers, 1000.5)
        assert "replay" in reason
        _, later = detector.inspect("203.0.113.7", "GET", "/api/chats", headers, 1010.0)
        assert "replay" not in later

    def test_what_the_detector_counts_is_what_it_saw(self):
        detector = _detector()
        detector.inspect("203.0.113.7", "GET", "/api/chats", [("user-agent", "sqlmap/1.7.11#stable (x)")], 1000.0)
        stats = detector.stats()
        assert stats["total_probes_detected"] == 1
        assert detector.inspected() == 1
        assert detector.holds("203.0.113.7")
        assert not detector.holds("203.0.113.8")

    def test_the_status_route_is_never_told_how_much_traffic_the_node_serves(self):
        """Тот же довод, что находка №11 BMP: счётчик запросов — сигнал о чужой
        активности, а `/stealth-status` открыт любому вошедшему пользователю."""
        assert "total_requests_inspected" not in _detector().stats()

    def test_two_workers_share_what_the_detector_remembers(self):
        """Проводка проверяется сквозь мост, а не только на сторе.

        Набор соответствия гоняет `RedisSightings`/`RedisRoll` напрямую и не
        видит порядок вызовов: детектор читает backbone в конструкторе, поэтому
        `bmp_connect_redis` обязан случиться раньше. Здесь проверяется именно
        это — два экземпляра (то есть два воркера) видят состояние друг друга.
        """
        import os

        url = os.environ.get("VORTEX_TEST_REDIS_URL", "redis://127.0.0.1:6379/9")
        prefix = f"vortex-test:probe-wiring:{os.getpid()}"
        try:
            connected = vortex_chat.bmp_connect_redis(url, None, prefix)
        except RuntimeError as error:
            if "VORTEX_TEST_REDIS_URL" in os.environ:
                raise
            pytest.skip(f"Redis недоступен ({error})")
        if not connected:
            pytest.skip("Redis не подключён")

        first, second = vortex_chat.ProbeDetector(), vortex_chat.ProbeDetector()
        assert first.is_shared and second.is_shared

        headers = [("user-agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0"), ("cookie", "a=1")]
        first.inspect("203.0.113.9", "GET", "/api/chats", headers, 1000.0)
        _, seen_by_second = second.inspect("203.0.113.9", "GET", "/api/chats", headers, 1000.5)
        assert "replay" in seen_by_second, seen_by_second

        first.inspect("203.0.113.9", "GET", "/api/chats", [("user-agent", "sqlmap/1.7 (x)")], 2000.0)
        assert second.holds("203.0.113.9")

    def test_the_stores_are_bounded_and_can_be_emptied(self):
        detector = _detector()
        for index in range(50):
            detector.inspect("203.0.113.7", "GET", f"/api/chats/{index}", [], 1000.0 + index)
        assert detector.stats()["fingerprint_cache_size"] > 0
        detector.forget_stale(1_000_000.0)
        assert detector.stats()["fingerprint_cache_size"] == 0

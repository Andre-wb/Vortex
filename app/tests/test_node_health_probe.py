"""
test_node_health_probe.py — проба живости узла ходит по существующему пути.

Роут называется `/health`; `/api/health` не объявлялся никогда, поэтому
`probe_node`, фоновая проверка узлов федерации и замер RTT в smart_relay
получали 404 на каждый запрос: узел всегда выглядел недоступным.

Покрывает:
  - `/health` отвечает и на GET, и на HEAD (проба RTT шлёт HEAD);
  - `probe_node` запрашивает `/health`, а не `/api/health`;
  - отсутствующие в ответе поля не приезжают пустыми строками — иначе
    повторная верификация затирала бы сохранённое имя узла.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from app.federation.trusted_nodes import NodeSandbox

NODE_URL = "https://node.example.com"


class TestHealthRoute:
    def test_health_answers_get(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_health_answers_head_without_a_body(self, client):
        r = client.head("/health")
        assert r.status_code == 200
        assert r.content == b""

    def test_the_path_the_probes_used_is_still_not_a_route(self, client):
        assert client.get("/api/health").status_code == 404


class TestProbeNode:
    async def test_the_probe_asks_for_the_route_that_exists(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=f"{NODE_URL}/health", json={"status": "ok", "version": "1.0.0"})
        info = await NodeSandbox.probe_node(NODE_URL)
        assert info["version"] == "1.0.0"

    async def test_a_node_that_names_nothing_reports_nothing(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=f"{NODE_URL}/health", json={"status": "ok"})
        info = await NodeSandbox.probe_node(NODE_URL)
        assert info == {}, "пустое поле затёрло бы уже сохранённое значение"

    async def test_an_empty_field_is_the_same_as_no_field(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=f"{NODE_URL}/health",
            json={"status": "ok", "node_name": "", "node_id": "", "version": ""},
        )
        info = await NodeSandbox.probe_node(NODE_URL)
        assert info == {}

    async def test_what_the_node_did_report_is_kept(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url=f"{NODE_URL}/health",
            json={"status": "ok", "node_name": "Alpha", "node_id": "abc123", "version": "2.0"},
        )
        info = await NodeSandbox.probe_node(NODE_URL)
        assert info == {"name": "Alpha", "node_id": "abc123", "version": "2.0"}

    async def test_a_stored_name_survives_a_node_that_stopped_reporting_one(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=f"{NODE_URL}/health", json={"status": "ok", "version": "1.0.0"})
        info = await NodeSandbox.probe_node(NODE_URL)
        assert info.get("name", "Alpha") == "Alpha"

    async def test_an_answer_that_is_not_a_vortex_node_is_refused(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=f"{NODE_URL}/health", json={"nginx": "welcome"})
        with pytest.raises(ValueError):
            await NodeSandbox.probe_node(NODE_URL)

    async def test_an_answer_that_is_not_an_object_is_refused(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(url=f"{NODE_URL}/health", json=["ok"])
        with pytest.raises(ValueError):
            await NodeSandbox.probe_node(NODE_URL)


class TestRelayProbe:
    def test_the_relay_measures_rtt_against_the_route_that_exists(self):
        import inspect

        from app.transport import smart_relay

        source = inspect.getsource(smart_relay.SmartRelayRouter.probe_peer)
        assert "/health" in source
        assert "/api/health" not in source

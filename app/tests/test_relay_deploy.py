"""
test_relay_deploy.py — автоматический передеплой релеев после ротации секретов.

Покрывает app/transport/relay_deploy.py:
  - подпись SigV4 (сверка с официальным тест-вектором AWS)
  - каждая цель молчит, пока не настроена полностью
  - Cloudflare Worker, Lambda@Edge + CloudFront, Azure zipdeploy, Caddy
  - повторные попытки в пределах grace-окна
"""
from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from io import BytesIO

import pytest

from app.config import Config
from app.transport import relay_deploy as rd

# Официальный вектор AWS SigV4 «get-vanilla».
AWS_TEST_KEY = "AKIDEXAMPLE"
AWS_TEST_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"  # noqa: S105
AWS_TEST_SIGNATURE = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"


class FakeResponse:
    def __init__(self, status_code=200, text="", json_body=None, headers=None):
        self.status_code = status_code
        self.text = text
        self._json = json_body or {}
        self.headers = headers or {}

    def json(self):
        return self._json


class FakeClient:
    """Подменяет httpx.AsyncClient и записывает все вызовы."""

    calls: list[dict] = []
    responses: dict[str, list[FakeResponse]] = {}

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def _record(self, method, url, **kwargs):
        FakeClient.calls.append({"method": method, "url": url, **kwargs})
        queue = FakeClient.responses.get(method, [])
        return queue.pop(0) if queue else FakeResponse()

    async def put(self, url, **kwargs):
        return await self._record("put", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self._record("post", url, **kwargs)

    async def get(self, url, **kwargs):
        return await self._record("get", url, **kwargs)


@pytest.fixture(autouse=True)
def isolate_last_run():
    """Итог прогона глобальный — не даём ему протечь в другие тесты."""
    saved = dict(rd._last_run)
    yield
    rd._last_run.clear()
    rd._last_run.update(saved)


@pytest.fixture
def fake_http(monkeypatch):
    import httpx
    FakeClient.calls = []
    FakeClient.responses = {}
    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    return FakeClient


class TestSigV4:
    def test_matches_aws_test_vector(self):
        headers = rd.sigv4_headers(
            "GET", "service", "us-east-1", "example.amazonaws.com", "/", "", b"",
            AWS_TEST_KEY, AWS_TEST_SECRET,
            now=datetime(2015, 8, 30, 12, 36, 0, tzinfo=timezone.utc),
        )
        assert f"Signature={AWS_TEST_SIGNATURE}" in headers["Authorization"]
        assert "SignedHeaders=host;x-amz-date" in headers["Authorization"]
        assert headers["x-amz-date"] == "20150830T123600Z"

    def test_extra_headers_are_signed(self):
        headers = rd.sigv4_headers(
            "PUT", "lambda", "us-east-1", "lambda.us-east-1.amazonaws.com",
            "/x", "", b"{}", AWS_TEST_KEY, AWS_TEST_SECRET,
            extra={"content-type": "application/json"},
        )
        assert "content-type" in headers["Authorization"]

    def test_payload_changes_signature(self):
        now = datetime(2015, 8, 30, 12, 36, 0, tzinfo=timezone.utc)
        args = ("PUT", "lambda", "us-east-1", "h", "/p", "")
        one = rd.sigv4_headers(*args, b"a", AWS_TEST_KEY, AWS_TEST_SECRET, now=now)
        two = rd.sigv4_headers(*args, b"b", AWS_TEST_KEY, AWS_TEST_SECRET, now=now)
        assert one["Authorization"] != two["Authorization"]


class TestConfiguration:
    def test_all_targets_idle_by_default(self, monkeypatch):
        for key in ("CLOUDFLARE_API_TOKEN", "AWS_ACCESS_KEY_ID",
                    "AZURE_FUNCTION_APP", "NAIVE_CADDYFILE_PATH"):
            monkeypatch.setattr(Config, key, "")
        assert [t.name for t in rd.TARGETS if t.configured] == []

    async def test_deploy_all_without_targets_is_noop(self, monkeypatch):
        for key in ("CLOUDFLARE_API_TOKEN", "AWS_ACCESS_KEY_ID",
                    "AZURE_FUNCTION_APP", "NAIVE_CADDYFILE_PATH"):
            monkeypatch.setattr(Config, key, "")
        assert await rd.deploy_all() == {}

    def test_partial_config_is_not_enough(self, monkeypatch):
        monkeypatch.setattr(Config, "CLOUDFLARE_API_TOKEN", "token")
        monkeypatch.setattr(Config, "CLOUDFLARE_ACCOUNT_ID", "")
        assert rd.CloudflareWorkerTarget().configured is False


@pytest.fixture
def cloudflare_configured(monkeypatch):
    monkeypatch.setattr(Config, "CLOUDFLARE_API_TOKEN", "cf-token")
    monkeypatch.setattr(Config, "CLOUDFLARE_ACCOUNT_ID", "acc-1")
    monkeypatch.setattr(Config, "CDN_WORKER_SCRIPT_NAME", "vortex-relay")
    monkeypatch.setattr(Config, "CDN_WORKER_KV_NAMESPACE_ID", "kv-1")


class TestCloudflare:
    async def test_uploads_worker_module(self, fake_http, cloudflare_configured):
        detail = await rd.CloudflareWorkerTarget().deploy()

        call = fake_http.calls[0]
        assert call["method"] == "put"
        assert call["url"].endswith("/accounts/acc-1/workers/scripts/vortex-relay")
        assert call["headers"]["Authorization"] == "Bearer cf-token"
        metadata = json.loads(call["files"]["metadata"][1])
        assert metadata["main_module"] == "worker.js"
        assert metadata["bindings"] == [
            {"type": "kv_namespace", "name": "VORTEX_KV", "namespace_id": "kv-1"}]
        assert "AUTH_SECRET_PREV" in call["files"]["worker.js"][1]
        assert Config.CDN_WORKER_KV_SECRET in call["files"]["worker.js"][1]
        assert "updated" in detail

    async def test_refuses_without_kv_namespace(self, fake_http, cloudflare_configured,
                                                monkeypatch):
        """Без namespace_id заливка сняла бы KV-привязку у живого Worker."""
        monkeypatch.setattr(Config, "CDN_WORKER_KV_NAMESPACE_ID", "")
        with pytest.raises(rd.DeployError, match="KV binding"):
            await rd.CloudflareWorkerTarget().deploy()
        assert fake_http.calls == []

    async def test_api_error_raises(self, fake_http, cloudflare_configured):
        fake_http.responses["put"] = [FakeResponse(403, text="forbidden")]
        with pytest.raises(rd.DeployError, match="403"):
            await rd.CloudflareWorkerTarget().deploy()


@pytest.fixture
def aws_configured(monkeypatch):
    monkeypatch.setattr(Config, "AWS_ACCESS_KEY_ID", AWS_TEST_KEY)
    monkeypatch.setattr(Config, "AWS_SECRET_ACCESS_KEY", AWS_TEST_SECRET)
    monkeypatch.setattr(Config, "AWS_LAMBDA_FUNCTION_NAME", "VortexRelay")
    monkeypatch.setattr(Config, "AWS_CLOUDFRONT_DISTRIBUTION_ID", "E123")


ARN = "arn:aws:lambda:us-east-1:1234:function:VortexRelay"
DIST_XML = (
    '<?xml version="1.0"?>'
    '<DistributionConfig xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">'
    "<CallerReference>ref</CallerReference>"
    f"<LambdaFunctionARN>{ARN}:7</LambdaFunctionARN>"
    "</DistributionConfig>"
)


class TestAWSLambdaEdge:
    async def test_publishes_and_repoints_distribution(self, fake_http, aws_configured):
        fake_http.responses["put"] = [
            FakeResponse(200, json_body={"FunctionArn": f"{ARN}:8"}),
            FakeResponse(200),
        ]
        fake_http.responses["get"] = [
            FakeResponse(200, text=DIST_XML, headers={"ETag": "etag-1"})]

        detail = await rd.AWSLambdaEdgeTarget().deploy()

        code_call, dist_call = fake_http.calls[0], fake_http.calls[2]
        assert code_call["url"].endswith("/functions/VortexRelay/code")
        body = json.loads(code_call["content"])
        assert body["Publish"] is True
        with zipfile.ZipFile(BytesIO(rd.base64.b64decode(body["ZipFile"]))) as zf:
            assert zf.namelist() == ["index.js"]
            assert "AUTH_SECRET_PREV" in zf.read("index.js").decode()

        assert dist_call["headers"]["if-match"] == "etag-1"
        sent = dist_call["content"].decode()
        assert f"<LambdaFunctionARN>{ARN}:8</LambdaFunctionARN>" in sent
        assert sent.startswith("<DistributionConfig")
        assert "8" in detail

    async def test_fails_when_distribution_has_no_association(self, fake_http,
                                                              aws_configured):
        fake_http.responses["put"] = [FakeResponse(200, json_body={"FunctionArn": f"{ARN}:8"})]
        fake_http.responses["get"] = [FakeResponse(
            200, text='<DistributionConfig xmlns="x"><CallerReference>r</CallerReference>'
                      "</DistributionConfig>", headers={"ETag": "e"})]
        with pytest.raises(rd.DeployError, match="no association"):
            await rd.AWSLambdaEdgeTarget().deploy()

    def test_swap_arn_handles_unversioned_association(self):
        xml = (f'<DistributionConfig xmlns="x"><LambdaFunctionARN>{ARN}'
               "</LambdaFunctionARN></DistributionConfig>")
        out = rd.AWSLambdaEdgeTarget._swap_arn(xml, f"{ARN}:3")
        assert f"<LambdaFunctionARN>{ARN}:3</LambdaFunctionARN>" in out

    def test_swap_arn_ignores_other_functions(self):
        other = "arn:aws:lambda:us-east-1:1234:function:SomethingElse:1"
        xml = (f'<DistributionConfig xmlns="x"><LambdaFunctionARN>{other}'
               "</LambdaFunctionARN></DistributionConfig>")
        assert rd.AWSLambdaEdgeTarget._swap_arn(xml, f"{ARN}:3") is None

    async def test_lambda_error_raises(self, fake_http, aws_configured):
        fake_http.responses["put"] = [FakeResponse(400, text="bad request")]
        with pytest.raises(rd.DeployError, match="UpdateFunctionCode 400"):
            await rd.AWSLambdaEdgeTarget().deploy()


class TestAzure:
    async def test_zipdeploy_layout(self, fake_http, monkeypatch):
        monkeypatch.setattr(Config, "AZURE_FUNCTION_APP", "vortex-fn")
        monkeypatch.setattr(Config, "AZURE_PUBLISH_USER", "$vortex")
        monkeypatch.setattr(Config, "AZURE_PUBLISH_PASSWORD", "pw")

        await rd.AzureFunctionTarget().deploy()

        call = fake_http.calls[0]
        assert call["url"] == "https://vortex-fn.scm.azurewebsites.net/api/zipdeploy"
        assert call["auth"] == ("$vortex", "pw")
        with zipfile.ZipFile(BytesIO(call["content"])) as zf:
            assert sorted(zf.namelist()) == [
                "VortexRelay/function.json", "VortexRelay/index.js", "host.json"]
            trigger = json.loads(zf.read("VortexRelay/function.json"))
            assert trigger["bindings"][0]["route"] == "api/1/objects"
            assert "AUTH_SECRET_PREV" in zf.read("VortexRelay/index.js").decode()


class TestCaddy:
    async def test_writes_config_and_reloads(self, fake_http, tmp_path, monkeypatch):
        caddyfile = tmp_path / "Caddyfile"
        monkeypatch.setattr(Config, "NAIVE_CADDYFILE_PATH", str(caddyfile))
        monkeypatch.setattr(Config, "CADDY_ADMIN_URL", "http://127.0.0.1:2019")

        await rd.CaddyTarget().deploy()

        written = caddyfile.read_text()
        assert Config.NAIVE_USERNAME in written
        assert Config.NAIVE_PROBE_DOMAIN in written
        call = fake_http.calls[0]
        assert call["url"] == "http://127.0.0.1:2019/load"
        assert call["headers"]["Content-Type"] == "text/caddyfile"
        assert call["content"].decode() == written

    async def test_write_failure_is_reported(self, fake_http, tmp_path, monkeypatch):
        monkeypatch.setattr(Config, "NAIVE_CADDYFILE_PATH",
                            str(tmp_path / "missing" / "Caddyfile"))
        with pytest.raises(rd.DeployError, match="cannot write"):
            await rd.CaddyTarget().deploy()


class _FlakyTarget(rd.RelayTarget):
    name = "flaky"

    def __init__(self, fail_times: int):
        self.attempts = 0
        self._fail_times = fail_times

    @property
    def configured(self) -> bool:
        return True

    async def deploy(self) -> str:
        self.attempts += 1
        if self.attempts <= self._fail_times:
            raise rd.DeployError("temporary failure")
        return "ok"


class TestRetry:
    async def test_retries_until_success(self, monkeypatch):
        target = _FlakyTarget(fail_times=2)
        monkeypatch.setattr(rd, "TARGETS", (target,))
        monkeypatch.setattr(rd.asyncio, "sleep", _instant_sleep)

        summary = await rd.deploy_all_with_retry(3600, first_backoff=1)
        assert summary["flaky"] == {"ok": True, "detail": "ok"}
        assert target.attempts == 3

    async def test_gives_up_when_window_closes(self, monkeypatch):
        target = _FlakyTarget(fail_times=99)
        monkeypatch.setattr(rd, "TARGETS", (target,))
        monkeypatch.setattr(rd.asyncio, "sleep", _instant_sleep)

        summary = await rd.deploy_all_with_retry(0, first_backoff=1)
        assert summary["flaky"]["ok"] is False
        assert target.attempts == 1

    async def test_status_reflects_last_run(self, monkeypatch):
        target = _FlakyTarget(fail_times=0)
        monkeypatch.setattr(rd, "TARGETS", (target,))
        await rd.deploy_all_with_retry(60)
        status = rd.deploy_status()
        assert status["configured_targets"] == ["flaky"]
        assert status["last_result"]["flaky"]["ok"] is True


class TestRotationTriggersDeploy:
    async def test_rotation_pushes_to_relays_within_the_window(self, monkeypatch):
        from app.security import secret_rotation as sr

        seen: dict = {}

        async def fake_deploy(deadline_seconds, first_backoff=60.0):
            seen["deadline"] = deadline_seconds
            return {}

        monkeypatch.setattr(rd, "deploy_all_with_retry", fake_deploy)
        monkeypatch.setattr(Config, "SECRET_ROTATION_HOURS", 24)

        await sr.rotator._redeploy_relays()
        # Дедлайн — ровно окно, в течение которого релей принимает прежний секрет.
        assert seen["deadline"] == 24 * 3600


async def _instant_sleep(_seconds):
    return None

"""
app/transport/relay_deploy.py — передеплой релеев после ротации секретов.

Ротация меняет секрет на ноде, но задеплоенный Worker/Lambda/Function и
локальный Caddy продолжают проверять старый. Здесь они обновляются сами: код
собирается из тех же шаблонов, что и при ручном деплое, и заливается через
HTTP API провайдеров (без CLI и облачных SDK — только httpx).

Каждая цель включается, только когда заданы все её переменные. Неудача не
рвёт связь: прежний секрет принимается ещё одно окно, поэтому попытки
повторяются с растущей паузой, пока окно не закончится.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import json
import logging
import re
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from app.config import Config

logger = logging.getLogger(__name__)

_TIMEOUT = 60.0

# Lambda@Edge живёт только в us-east-1 — CloudFront реплицирует её сам.
_EDGE_REGION = "us-east-1"


class DeployError(Exception):
    """Передеплой цели не удался."""


# AWS Signature V4


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k = _sign(f"AWS4{secret}".encode(), datestamp)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


def sigv4_headers(
    method: str,
    service: str,
    region: str,
    host: str,
    path: str,
    query: str,
    payload: bytes,
    access_key: str,
    secret_key: str,
    extra: dict | None = None,
    now: datetime | None = None,
) -> dict:
    """Заголовки Authorization/X-Amz-* для запроса к AWS."""
    t = now or datetime.now(timezone.utc)
    amzdate = t.strftime("%Y%m%dT%H%M%SZ")
    datestamp = t.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(payload).hexdigest()

    headers = {
        "host": host,
        "x-amz-date": amzdate,
    }
    for key, value in (extra or {}).items():
        headers[key.lower()] = value

    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{k}:{headers[k].strip()}\n" for k in sorted(headers))
    canonical_request = "\n".join(
        [
            method,
            path,
            query,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )

    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amzdate,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ]
    )
    signature = hmac.new(
        _signing_key(secret_key, datestamp, region, service),
        string_to_sign.encode(),
        hashlib.sha256,
    ).hexdigest()

    result = {k: v for k, v in headers.items() if k != "host"}
    result["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
    return result


def _zip_bytes(files: dict[str, str]) -> bytes:
    """Детерминированный ZIP-архив из карты «путь → содержимое»."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            zf.writestr(info, content)
    return buf.getvalue()


# Цели передеплоя


class RelayTarget:
    """Одна цель передеплоя. Активна только если полностью настроена."""

    name = "base"

    @property
    def configured(self) -> bool:
        raise NotImplementedError

    async def deploy(self) -> str:
        raise NotImplementedError


class CloudflareWorkerTarget(RelayTarget):
    """Cloudflare Worker: заливка модуля через Workers Script API."""

    name = "cloudflare_worker"

    @property
    def configured(self) -> bool:
        return bool(Config.CLOUDFLARE_API_TOKEN and Config.CLOUDFLARE_ACCOUNT_ID and Config.CDN_WORKER_SCRIPT_NAME)

    async def deploy(self) -> str:
        import httpx

        from app.transport.stealth_level4 import stealth_l4

        backend = Config.CDN_WORKER_BACKEND_URL or f"http://127.0.0.1:{Config.PORT}"
        script = stealth_l4.cdn_workers.generate_worker_script(backend_url=backend)

        bindings = []
        if Config.CDN_WORKER_KV_NAMESPACE_ID:
            bindings.append(
                {
                    "type": "kv_namespace",
                    "name": "VORTEX_KV",
                    "namespace_id": Config.CDN_WORKER_KV_NAMESPACE_ID,
                }
            )
        else:
            # Без namespace_id API снял бы существующую привязку KV и Worker
            # начал бы падать на env.VORTEX_KV.
            raise DeployError(
                "CDN_WORKER_KV_NAMESPACE_ID is required to redeploy the Worker without dropping its KV binding"
            )

        metadata = {"main_module": "worker.js", "bindings": bindings}
        url = (
            f"https://api.cloudflare.com/client/v4/accounts/"
            f"{Config.CLOUDFLARE_ACCOUNT_ID}/workers/scripts/"
            f"{Config.CDN_WORKER_SCRIPT_NAME}"
        )

        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            resp = await c.put(
                url,
                headers={"Authorization": f"Bearer {Config.CLOUDFLARE_API_TOKEN}"},
                files={
                    "metadata": (None, json.dumps(metadata), "application/json"),
                    "worker.js": ("worker.js", script, "application/javascript+module"),
                },
            )
        if resp.status_code >= 400:
            raise DeployError(f"Cloudflare API {resp.status_code}: {resp.text[:300]}")
        return f"worker {Config.CDN_WORKER_SCRIPT_NAME} updated"


class AWSLambdaEdgeTarget(RelayTarget):
    """
    Lambda@Edge: публикация новой версии и переассоциация с CloudFront.

    Переменных окружения у Lambda@Edge нет, поэтому секрет живёт в коде и
    обновление всегда означает публикацию версии. CloudFront ссылается на
    конкретную версию, так что distribution надо перенацелить на новую.
    """

    name = "aws_lambda_edge"

    @property
    def configured(self) -> bool:
        return bool(
            Config.AWS_ACCESS_KEY_ID
            and Config.AWS_SECRET_ACCESS_KEY
            and Config.AWS_LAMBDA_FUNCTION_NAME
            and Config.AWS_CLOUDFRONT_DISTRIBUTION_ID
        )

    async def deploy(self) -> str:
        from app.transport.stealth_level4 import stealth_l4

        script = stealth_l4.aws_lambda_relay.generate_lambda_script()
        version_arn = await self._publish_code(script)
        await self._point_distribution_at(version_arn)
        return f"lambda published as {version_arn.rsplit(':', 1)[-1]}"

    async def _publish_code(self, script: str) -> str:
        import httpx

        payload = json.dumps(
            {
                "ZipFile": base64.b64encode(_zip_bytes({"index.js": script})).decode(),
                "Publish": True,
            }
        ).encode()
        host = f"lambda.{_EDGE_REGION}.amazonaws.com"
        path = f"/2015-03-31/functions/{Config.AWS_LAMBDA_FUNCTION_NAME}/code"
        headers = sigv4_headers(
            "PUT",
            "lambda",
            _EDGE_REGION,
            host,
            path,
            "",
            payload,
            Config.AWS_ACCESS_KEY_ID,
            Config.AWS_SECRET_ACCESS_KEY,
            extra={"content-type": "application/json"},
        )
        headers["content-type"] = "application/json"

        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            resp = await c.put(f"https://{host}{path}", content=payload, headers=headers)
        if resp.status_code >= 400:
            raise DeployError(f"Lambda UpdateFunctionCode {resp.status_code}: {resp.text[:300]}")
        arn = resp.json().get("FunctionArn", "")
        if not arn or ":" not in arn:
            raise DeployError("Lambda response has no FunctionArn")
        return arn

    async def _point_distribution_at(self, version_arn: str) -> None:
        import httpx

        host = "cloudfront.amazonaws.com"
        path = f"/2020-05-31/distribution/{Config.AWS_CLOUDFRONT_DISTRIBUTION_ID}/config"
        get_headers = sigv4_headers(
            "GET",
            "cloudfront",
            "us-east-1",
            host,
            path,
            "",
            b"",
            Config.AWS_ACCESS_KEY_ID,
            Config.AWS_SECRET_ACCESS_KEY,
        )

        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            current = await c.get(f"https://{host}{path}", headers=get_headers)
            if current.status_code >= 400:
                raise DeployError(f"CloudFront GetDistributionConfig {current.status_code}: {current.text[:300]}")
            etag = current.headers.get("ETag", "")
            body = self._swap_arn(current.text, version_arn)
            if body is None:
                raise DeployError(f"distribution has no association with {Config.AWS_LAMBDA_FUNCTION_NAME}")

            put_headers = sigv4_headers(
                "PUT",
                "cloudfront",
                "us-east-1",
                host,
                path,
                "",
                body.encode(),
                Config.AWS_ACCESS_KEY_ID,
                Config.AWS_SECRET_ACCESS_KEY,
                extra={"content-type": "text/xml", "if-match": etag},
            )
            put_headers["content-type"] = "text/xml"
            put_headers["if-match"] = etag
            resp = await c.put(f"https://{host}{path}", content=body.encode(), headers=put_headers)
        if resp.status_code >= 400:
            raise DeployError(f"CloudFront UpdateDistribution {resp.status_code}: {resp.text[:300]}")

    @staticmethod
    def _swap_arn(config_xml: str, version_arn: str) -> str | None:
        """
        Подставляет новую версию функции во все её ассоциации.

        Ответ GetDistributionConfig обёрнут в <DistributionConfig>, но PUT
        ожидает именно этот элемент — остальное берётся из URL и If-Match.
        """
        unversioned = version_arn.rsplit(":", 1)[0]
        pattern = re.compile(r"(<LambdaFunctionARN>)" + re.escape(unversioned) + r"(:\d+)?(</LambdaFunctionARN>)")
        body, count = pattern.subn(r"\g<1>" + version_arn + r"\g<3>", config_xml)
        if not count:
            return None
        start = body.find("<DistributionConfig")
        end = body.rfind("</DistributionConfig>")
        if start == -1 or end == -1:
            return None
        return body[start : end + len("</DistributionConfig>")]


class AzureFunctionTarget(RelayTarget):
    """Azure Function: ZIP-деплой через Kudu с публикационными данными."""

    name = "azure_function"

    HOST_JSON = json.dumps({"version": "2.0"})
    FUNCTION_JSON = json.dumps(
        {
            "bindings": [
                {
                    "authLevel": "anonymous",
                    "type": "httpTrigger",
                    "direction": "in",
                    "name": "req",
                    "methods": ["get", "post"],
                    "route": "api/1/objects",
                },
                {"type": "http", "direction": "out", "name": "res"},
            ]
        }
    )

    @property
    def configured(self) -> bool:
        return bool(Config.AZURE_FUNCTION_APP and Config.AZURE_PUBLISH_USER and Config.AZURE_PUBLISH_PASSWORD)

    async def deploy(self) -> str:
        import httpx

        from app.transport.stealth_level4 import stealth_l4

        script = stealth_l4.azure_cdn_relay.generate_function_script()
        archive = _zip_bytes(
            {
                "host.json": self.HOST_JSON,
                "VortexRelay/function.json": self.FUNCTION_JSON,
                "VortexRelay/index.js": script,
            }
        )
        url = f"https://{Config.AZURE_FUNCTION_APP}.scm.azurewebsites.net/api/zipdeploy"

        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            resp = await c.post(
                url,
                content=archive,
                headers={"Content-Type": "application/zip"},
                auth=(Config.AZURE_PUBLISH_USER, Config.AZURE_PUBLISH_PASSWORD),
            )
        if resp.status_code >= 400:
            raise DeployError(f"Azure zipdeploy {resp.status_code}: {resp.text[:300]}")
        return f"function app {Config.AZURE_FUNCTION_APP} updated"


class CaddyTarget(RelayTarget):
    """Caddy для NaïveProxy: перезапись Caddyfile и reload через admin API."""

    name = "naiveproxy_caddy"

    @property
    def configured(self) -> bool:
        return bool(Config.NAIVE_CADDYFILE_PATH)

    async def deploy(self) -> str:
        import httpx

        from app.transport.stealth_level4 import stealth_l4

        config = stealth_l4.naiveproxy.generate_caddy_config()
        path = Path(Config.NAIVE_CADDYFILE_PATH)
        try:
            path.write_text(config)
        except OSError as e:
            raise DeployError(f"cannot write {path}: {e}") from e

        if not Config.CADDY_ADMIN_URL:
            return f"{path} rewritten (no admin API configured)"

        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            resp = await c.post(
                f"{Config.CADDY_ADMIN_URL.rstrip('/')}/load",
                content=config.encode(),
                headers={"Content-Type": "text/caddyfile"},
            )
        if resp.status_code >= 400:
            raise DeployError(f"Caddy admin API {resp.status_code}: {resp.text[:300]}")
        return f"{path} rewritten and reloaded"


TARGETS: tuple[RelayTarget, ...] = (
    CloudflareWorkerTarget(),
    AWSLambdaEdgeTarget(),
    AzureFunctionTarget(),
    CaddyTarget(),
)

# Итог последнего прогона — попадает в статус level 4.
_last_run: dict[str, dict] = {}


def deploy_status() -> dict:
    return {
        "configured_targets": sorted(t.name for t in TARGETS if t.configured),
        "last_result": dict(_last_run),
    }


async def deploy_targets(targets: list[RelayTarget]) -> dict[str, dict]:
    """Прогон конкретного списка целей. Возвращает результат по каждой."""
    results: dict[str, dict] = {}

    async def run(target: RelayTarget) -> None:
        try:
            detail = await target.deploy()
            results[target.name] = {"ok": True, "detail": detail}
            logger.info("Relay deploy: %s — %s", target.name, detail)
        except Exception as e:
            results[target.name] = {"ok": False, "detail": str(e)[:300]}
            logger.warning("Relay deploy: %s failed — %s", target.name, e)

    await asyncio.gather(*(run(t) for t in targets))
    return results


async def deploy_all() -> dict[str, dict]:
    """Один проход по всем настроенным целям."""
    targets = [t for t in TARGETS if t.configured]
    if not targets:
        logger.info("Relay deploy: no targets configured, nothing to push")
        return {}
    return await deploy_targets(targets)


async def deploy_all_with_retry(deadline_seconds: float, first_backoff: float = 60.0) -> dict[str, dict]:
    """
    Повторяет передеплой не удавшихся целей, пока не истечёт grace-окно.

    Пока окно не закрылось, релей принимает и прежний секрет, поэтому неудачная
    попытка ничего не рвёт — важно лишь успеть до его конца.
    """
    started = time.monotonic()
    summary: dict[str, dict] = {}
    pending = [t for t in TARGETS if t.configured]
    backoff = first_backoff

    while pending:
        results = await deploy_targets(pending)
        summary.update(results)
        pending = [t for t in pending if not results.get(t.name, {}).get("ok")]
        if not pending:
            break
        left = deadline_seconds - (time.monotonic() - started)
        if left <= 0:
            logger.error(
                "Relay deploy: giving up on %s — grace window closed, these relays still expect the previous secret",
                ", ".join(t.name for t in pending),
            )
            break
        await asyncio.sleep(min(backoff, left))
        backoff = min(backoff * 2, Config.RELAY_DEPLOY_MAX_BACKOFF)

    _last_run.clear()
    _last_run.update(summary)
    return summary

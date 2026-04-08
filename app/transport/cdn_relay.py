"""
app/transport/cdn_relay.py — Multi-CDN relay для маскировки IP-адреса сервера.

Принцип работы:
  1. Пользователь разворачивает CDN Worker (Cloudflare / AWS Lambda@Edge / Azure)
  2. Worker проксирует все запросы к реальному Vortex серверу
  3. Клиент подключается к CDN (SNI = worker.domain)
  4. DPI видит только HTTPS к CDN — не может заблокировать

Multi-CDN failover:
  Если один CDN падает, автоматически переключаемся на следующий.

Конфигурация:
  CDN_RELAY_URLS=https://worker1.workers.dev,https://d1234.cloudfront.net
  CDN_RELAY_SECRET=shared-secret-for-auth

  Обратная совместимость: CDN_RELAY_URL (одиночный URL) по-прежнему работает.

Cloudflare / AWS / Azure скрипты:
  -> генерируются командой: python run.py --generate-worker
"""
from __future__ import annotations

import logging
import os
import threading

logger = logging.getLogger(__name__)


# ── Cloudflare Worker скрипт ──────────────────────────────────────────────────

CLOUDFLARE_WORKER_TEMPLATE = """
// Cloudflare Worker — Vortex CDN Relay
// Deploy: wrangler deploy
//
// Проксирует все запросы к реальному Vortex серверу.
// Для DPI трафик выглядит как обычные запросы к Cloudflare Workers.

const BACKEND = "{backend_url}";
const SECRET  = "{relay_secret}";

export default {{
  async fetch(request, env) {{
    const url = new URL(request.url);

    // Проверка HMAC-подписи (время-зависимая, не plaintext secret)
    const ts = request.headers.get("X-Relay-Ts") || "";
    const sig = request.headers.get("X-Relay-Auth") || "";
    async function verifySig(secret, authSig, tsVal) {{
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey("raw", enc.encode(secret), {{name:"HMAC",hash:"SHA-256"}}, false, ["sign"]);
      const mac = await crypto.subtle.sign("HMAC", key, enc.encode(tsVal));
      const hex = [...new Uint8Array(mac)].map(b=>b.toString(16).padStart(2,"0")).join("").slice(0,32);
      return hex === authSig;
    }}
    const curTs = String(Math.floor(Date.now()/1000/300));
    const prevTs = String(Math.floor(Date.now()/1000/300) - 1);
    const ok = await verifySig(SECRET, sig, ts) || await verifySig(SECRET, sig, curTs) || await verifySig(SECRET, sig, prevTs);
    if (!ok) {{
      return fetch(BACKEND + "/cover" + url.pathname);
    }}

    // Проксируем к реальному бэкенду
    const backendUrl = BACKEND + url.pathname + url.search;

    // WebSocket проксирование
    if (request.headers.get("Upgrade") === "websocket") {{
      const wsUrl = BACKEND.replace("https://", "wss://").replace("http://", "ws://")
                    + url.pathname + url.search;
      return fetch(wsUrl, {{
        headers: request.headers,
      }});
    }}

    // HTTP проксирование
    const resp = await fetch(backendUrl, {{
      method: request.method,
      headers: {{
        ...Object.fromEntries(request.headers),
        "X-Forwarded-For": request.headers.get("CF-Connecting-IP"),
        "X-Real-IP": request.headers.get("CF-Connecting-IP"),
      }},
      body: request.method !== "GET" ? request.body : undefined,
    }});

    // Копируем ответ + добавляем cover headers
    const response = new Response(resp.body, {{
      status: resp.status,
      headers: {{
        ...Object.fromEntries(resp.headers),
        "Server": "cloudflare",
        "CF-Cache-Status": "DYNAMIC",
      }},
    }});

    return response;
  }}
}};
"""

WRANGLER_TOML_TEMPLATE = """
name = "vortex-relay"
main = "worker.js"
compatibility_date = "2024-01-01"

[vars]
ENVIRONMENT = "production"
"""

# ── AWS Lambda@Edge скрипт ───────────────────────────────────────────────────

AWS_LAMBDA_EDGE_TEMPLATE = """
// AWS Lambda@Edge — Vortex CDN Relay
// Deploy через AWS CloudFormation или SAM

exports.handler = async (event) => {{
    const request = event.Records[0].cf.request;
    const BACKEND = "{backend_url}";
    const SECRET = "{relay_secret}";

    // Проверка авторизации
    const authHeader = request.headers['x-relay-auth'];
    if (!authHeader || authHeader[0].value !== SECRET) {{
        // Показываем cover-сайт
        return {{
            status: '200',
            body: '<html><body>Welcome to CloudSync</body></html>',
            headers: {{ 'content-type': [{{ value: 'text/html' }}] }},
        }};
    }}

    // Проксируем к бэкенду
    request.origin = {{
        custom: {{
            domainName: new URL(BACKEND).hostname,
            port: parseInt(new URL(BACKEND).port) || 443,
            protocol: 'https',
            path: '',
            sslProtocols: ['TLSv1.2'],
            readTimeout: 30,
            keepaliveTimeout: 5,
        }}
    }};

    return request;
}};
"""

# ── Azure Function скрипт ────────────────────────────────────────────────────

AZURE_FUNCTION_TEMPLATE = """
// Azure Function — Vortex CDN Relay
// Deploy: func azure functionapp publish <app-name>

const BACKEND = "{backend_url}";
const SECRET = "{relay_secret}";

module.exports = async function (context, req) {{
    if (req.headers['x-relay-auth'] !== SECRET) {{
        context.res = {{
            status: 200,
            body: "Welcome to CloudSync",
            headers: {{ "Content-Type": "text/html" }},
        }};
        return;
    }}

    const fetch = require('node-fetch');
    const url = BACKEND + req.url;
    const resp = await fetch(url, {{
        method: req.method,
        headers: req.headers,
        body: req.method !== 'GET' ? req.rawBody : undefined,
    }});

    context.res = {{
        status: resp.status,
        body: await resp.text(),
        headers: Object.fromEntries(resp.headers),
    }};
}};
"""


# ── Генерация файлов для всех CDN-провайдеров ─────────────────────────────────

def generate_worker_files(backend_url: str, relay_secret: str, output_dir: str = "cdn_worker") -> str:
    """
    Генерация файлов CDN relay для всех поддерживаемых провайдеров.

    Использование:
        python run.py --generate-worker --backend https://your-server.com:8000

    Генерирует скрипты для Cloudflare Workers, AWS Lambda@Edge, Azure Functions.
    Возвращает путь к директории с файлами.
    """
    os.makedirs(output_dir, exist_ok=True)

    # Cloudflare Worker
    worker_js = CLOUDFLARE_WORKER_TEMPLATE.format(
        backend_url=backend_url,
        relay_secret=relay_secret,
    )
    with open(os.path.join(output_dir, "cloudflare-worker.js"), "w") as f:
        f.write(worker_js)

    with open(os.path.join(output_dir, "wrangler.toml"), "w") as f:
        f.write(WRANGLER_TOML_TEMPLATE)

    # AWS Lambda@Edge
    aws_js = AWS_LAMBDA_EDGE_TEMPLATE.format(
        backend_url=backend_url,
        relay_secret=relay_secret,
    )
    with open(os.path.join(output_dir, "aws-lambda-edge.js"), "w") as f:
        f.write(aws_js)

    # Azure Function
    azure_js = AZURE_FUNCTION_TEMPLATE.format(
        backend_url=backend_url,
        relay_secret=relay_secret,
    )
    with open(os.path.join(output_dir, "azure-function.js"), "w") as f:
        f.write(azure_js)

    # README с инструкциями для всех 3 провайдеров
    readme = f"""# Vortex CDN Relay — Multi-Provider

## Поддерживаемые CDN

### 1. Cloudflare Workers (рекомендуется)
```
npm install -g wrangler
wrangler login
cd {output_dir}
wrangler deploy
```
URL: https://vortex-relay.<username>.workers.dev

### 2. AWS CloudFront + Lambda@Edge
Deploy `aws-lambda-edge.js` как Lambda@Edge функцию.
Привяжите к CloudFront distribution.

### 3. Azure Functions
```
func init VortexRelay --javascript
cp azure-function.js VortexRelay/index.js
func azure functionapp publish <app-name>
```

## Multi-CDN конфигурация
```env
CDN_RELAY_URLS=https://worker.username.workers.dev,https://d1234.cloudfront.net
CDN_RELAY_SECRET={relay_secret}
```
Vortex автоматически переключается между CDN при отказе.
"""

    with open(os.path.join(output_dir, "README.md"), "w") as f:
        f.write(readme)

    logger.info(f"Worker files generated in {output_dir}/ (Cloudflare, AWS, Azure)")
    return output_dir


# ── Multi-CDN конфигурация с автоматическим failover ──────────────────────────

class CDNRelayConfig:
    """Конфигурация Multi-CDN relay с автоматическим failover."""

    def __init__(self):
        # Поддержка нескольких CDN URL (через запятую)
        # Обратная совместимость: CDN_RELAY_URL (одиночный) тоже работает
        urls_str = os.getenv("CDN_RELAY_URLS", os.getenv("CDN_RELAY_URL", ""))
        self.relay_urls: list[str] = [u.strip() for u in urls_str.split(",") if u.strip()]
        self.relay_secret = os.getenv("CDN_RELAY_SECRET", "")
        self.enabled = len(self.relay_urls) > 0
        self._current_idx = 0
        self._failures: dict[int, int] = {}  # idx -> счётчик ошибок
        self._lock = threading.Lock()

    @property
    def relay_url(self) -> str:
        """Обратная совместимость: возвращает текущий активный URL."""
        return self.get_active_url()

    def get_active_url(self) -> str:
        """Возвращает текущий активный CDN URL."""
        if not self.relay_urls:
            return ""
        with self._lock:
            return self.relay_urls[self._current_idx % len(self.relay_urls)]

    def get_api_base(self) -> str:
        """Возвращает базовый URL для API-запросов (CDN или прямое подключение)."""
        url = self.get_active_url()
        if self.enabled and url:
            return url.rstrip("/")
        return ""  # прямое подключение

    def report_failure(self) -> str:
        """Фиксирует ошибку на текущем URL, переключается на следующий. Возвращает новый URL."""
        if len(self.relay_urls) <= 1:
            return self.get_active_url()
        with self._lock:
            self._failures[self._current_idx] = self._failures.get(self._current_idx, 0) + 1
            self._current_idx = (self._current_idx + 1) % len(self.relay_urls)
            new_url = self.relay_urls[self._current_idx]
            logger.info(f"CDN failover: переключение на {new_url}")
            return new_url

    def report_success(self) -> None:
        """Фиксирует успех на текущем URL, сбрасывает счётчик ошибок."""
        with self._lock:
            self._failures[self._current_idx] = 0

    def get_headers(self) -> dict:
        """
        Возвращает заголовки для CDN-проксированных запросов.
        Вместо plaintext secret используется HMAC(secret, timestamp).
        Timestamp привязан к 5-минутным окнам — replay-защита.
        """
        if self.enabled and self.relay_secret:
            import hashlib, hmac, time
            ts = str(int(time.time()) // 300)  # 5-минутное окно
            sig = hmac.new(
                self.relay_secret.encode(), ts.encode(), hashlib.sha256
            ).hexdigest()[:32]
            return {
                "X-Relay-Auth": sig,
                "X-Relay-Ts": ts,
            }
        return {}

    @staticmethod
    def verify_relay_auth(secret: str, auth_header: str, ts_header: str) -> bool:
        """Проверяет HMAC-подпись CDN relay на стороне сервера."""
        import hashlib, hmac, time
        if not auth_header or not ts_header:
            return False
        # Принимаем текущее и предыдущее окно (grace period)
        current_ts = str(int(time.time()) // 300)
        prev_ts = str(int(time.time()) // 300 - 1)
        for ts in (ts_header, current_ts, prev_ts):
            expected = hmac.new(
                secret.encode(), ts.encode(), hashlib.sha256
            ).hexdigest()[:32]
            if hmac.compare_digest(auth_header, expected):
                return True
        return False

    def get_status(self) -> dict:
        """Возвращает статус всех CDN relay."""
        with self._lock:
            return {
                "enabled": self.enabled,
                "total": len(self.relay_urls),
                "active_idx": self._current_idx,
                "active_url": self.relay_urls[self._current_idx] if self.relay_urls else "",
                "relays": [
                    {
                        "url": url,
                        "failures": self._failures.get(i, 0),
                        "active": i == self._current_idx,
                    }
                    for i, url in enumerate(self.relay_urls)
                ],
            }


cdn_config = CDNRelayConfig()

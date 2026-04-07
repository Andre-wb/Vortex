"""
app/transport/cover_traffic.py — Генератор покрывающего трафика и маскировка.

Два компонента:
  1. Cover Website — реалистичный сайт для DPI-сканеров (существующий)
  2. Cover Traffic Generator — генерирует фейковый трафик в WebSocket
     чтобы заполнить паузы и сделать трафик неотличимым от веб-серфинга

Паттерн реального серфинга:
  - Burst: загрузка страницы (10-50 запросов за 1-3 сек)
  - Silence: чтение (5-60 сек тишины)
  - Burst: клик, переход (снова 10-50 запросов)

Cover traffic имитирует этот паттерн, отправляя рандомные данные
с размерами типичных веб-ресурсов (HTML ~15K, CSS ~8K, JS ~30K, img ~50K).
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import secrets
import time

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

logger = logging.getLogger(__name__)
router = APIRouter(tags=["cover"])


# ── Cover Website (для DPI-сканеров) ─────────────────────────────────────────

# Several realistic pages that look like a real business website
COVER_PAGES = {
    "/": """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudSync Solutions — Enterprise File Sync</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;
color:#333;line-height:1.6}header{background:#1a1a2e;color:#fff;padding:20px 40px;display:flex;justify-content:space-between;
align-items:center}header h1{font-size:1.4em}nav a{color:#a0a0cc;text-decoration:none;margin-left:24px;font-size:.9em}
.hero{padding:80px 40px;text-align:center;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff}
.hero h2{font-size:2.5em;margin-bottom:16px}.hero p{font-size:1.2em;opacity:.9;max-width:600px;margin:0 auto 32px}
.btn{padding:12px 32px;background:#fff;color:#764ba2;border:none;border-radius:6px;font-size:1em;cursor:pointer;font-weight:600}
.features{padding:60px 40px;display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:32px;max-width:1200px;margin:0 auto}
.feature{padding:24px;border:1px solid #eee;border-radius:12px}.feature h3{margin-bottom:8px;color:#1a1a2e}
footer{background:#1a1a2e;color:#666;text-align:center;padding:24px;font-size:.85em}
</style></head><body>
<header><h1>CloudSync</h1><nav><a href="/about">About</a><a href="/pricing">Pricing</a><a href="/docs">Docs</a><a href="/contact">Contact</a></nav></header>
<div class="hero"><h2>Enterprise File Synchronization</h2><p>Secure, fast, and reliable file sync for teams of any size. 256-bit encryption, real-time collaboration.</p><button class="btn">Start Free Trial</button></div>
<div class="features">
<div class="feature"><h3>End-to-End Encryption</h3><p>Your files are encrypted before they leave your device. We never have access to your data.</p></div>
<div class="feature"><h3>Real-time Sync</h3><p>Changes propagate instantly across all connected devices. No delays, no conflicts.</p></div>
<div class="feature"><h3>Team Collaboration</h3><p>Share folders, set permissions, track changes. Built for modern teams.</p></div>
<div class="feature"><h3>99.99% Uptime</h3><p>Distributed infrastructure ensures your files are always accessible when you need them.</p></div>
</div>
<footer>&copy; 2024 CloudSync Solutions Ltd. All rights reserved. | <a href="/privacy" style="color:#888">Privacy</a> | <a href="/terms" style="color:#888">Terms</a></footer>
</body></html>""",

    "/about": """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>About — CloudSync</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;color:#333;line-height:1.6}
header{background:#1a1a2e;color:#fff;padding:20px 40px}header h1{font-size:1.4em}
.content{max-width:800px;margin:40px auto;padding:0 24px}h2{margin-bottom:16px;color:#1a1a2e}
p{margin-bottom:16px}footer{background:#1a1a2e;color:#666;text-align:center;padding:24px;font-size:.85em;margin-top:60px}
</style></head><body>
<header><h1>CloudSync</h1></header>
<div class="content"><h2>About CloudSync</h2>
<p>Founded in 2019, CloudSync Solutions provides enterprise-grade file synchronization services to businesses worldwide.</p>
<p>Our team of engineers and security experts has built a platform that combines ease of use with military-grade encryption.</p>
<p>With offices in London, Berlin, and Singapore, we serve over 10,000 businesses across 40 countries.</p>
<h2>Our Mission</h2><p>To make secure file collaboration accessible to every team, regardless of size or technical expertise.</p>
</div><footer>&copy; 2024 CloudSync Solutions Ltd.</footer></body></html>""",

    "/pricing": """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Pricing — CloudSync</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,sans-serif;color:#333;line-height:1.6}
header{background:#1a1a2e;color:#fff;padding:20px 40px}header h1{font-size:1.4em}
.plans{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:24px;max-width:1000px;margin:40px auto;padding:0 24px}
.plan{border:1px solid #ddd;border-radius:12px;padding:32px;text-align:center}.plan h3{font-size:1.3em;margin-bottom:8px}
.price{font-size:2.2em;font-weight:700;color:#764ba2;margin:16px 0}.plan ul{list-style:none;margin:16px 0}
.plan li{padding:6px 0;font-size:.95em;color:#555}
footer{background:#1a1a2e;color:#666;text-align:center;padding:24px;font-size:.85em;margin-top:60px}
</style></head><body>
<header><h1>CloudSync</h1></header>
<div class="plans">
<div class="plan"><h3>Starter</h3><div class="price">$9/mo</div><ul><li>5 users</li><li>50 GB storage</li><li>Basic encryption</li><li>Email support</li></ul></div>
<div class="plan" style="border-color:#764ba2;border-width:2px"><h3>Business</h3><div class="price">$29/mo</div><ul><li>25 users</li><li>500 GB storage</li><li>E2E encryption</li><li>Priority support</li><li>Admin dashboard</li></ul></div>
<div class="plan"><h3>Enterprise</h3><div class="price">Custom</div><ul><li>Unlimited users</li><li>Unlimited storage</li><li>SSO / SAML</li><li>Dedicated support</li><li>SLA 99.99%</li></ul></div>
</div><footer>&copy; 2024 CloudSync Solutions Ltd.</footer></body></html>""",
}


# ── HTTP/2 Multiplexing Cover (фейковые ресурсы для имитации SPA) ────────────

def _generate_fake_js() -> str:
    """Генерирует ~25-35KB реалистичного минифицированного JavaScript."""
    parts = [
        '!function(e,t){"use strict";',
        'var n=Object.create,r=Object.defineProperty,i=Object.getOwnPropertyDescriptor;',
        'var o=Object.getOwnPropertyNames,a=Object.getPrototypeOf,s=Object.prototype.hasOwnProperty;',
        'function l(e,t){for(var n in t)r(e,n,{get:t[n],enumerable:!0})}',
        'function c(e,t,n,o){if(t&&"object"==typeof t||"function"==typeof t)',
        'for(let a of o(t))s.call(e,a)||a===n||r(e,a,{get:()=>t[a],enumerable:!0});return e}',
        'function u(e){return c(r({},"__esModule",{value:!0}),e)}',
        'var d=e=>c(r({},"__esModule",{value:!0}),e);',
        'var f={};l(f,{createElement:()=>h,Fragment:()=>p,render:()=>m});',
        'function h(e,t){var n=arguments,r,i,o,a={};for(o in t)"key"!==o&&"ref"!==o&&(a[o]=t[o]);',
        'if(arguments.length>2)for(a.children=[],r=2;r<arguments.length;r++)a.children.push(n[r]);',
        'return{type:e,props:a,key:null,ref:null}}',
        'var p=Symbol("Fragment");',
        'function m(e,t){t.textContent="";t.appendChild(g(e))}',
        'function g(e){if(null==e||"boolean"==typeof e)return document.createTextNode("");',
        'if("string"==typeof e||"number"==typeof e)return document.createTextNode(String(e));',
        'if(Array.isArray(e)){var t=document.createDocumentFragment();',
        'e.forEach(function(e){t.appendChild(g(e))});return t}',
        'var t=document.createElement(e.type);for(var n in e.props){',
        'if("children"===n)continue;"className"===n?t.setAttribute("class",e.props[n]):',
        't.setAttribute(n,e.props[n])}if(e.props.children)t.appendChild(g(e.props.children));return t}',
    ]
    base = ''.join(parts)
    # Генерируем реалистичные функции для достижения ~30KB
    funcs = []
    for idx in range(200):
        name = f"_{chr(97 + idx % 26)}{idx}"
        funcs.append(f'function {name}(a,b){{return a&&b?a+b:null}}')
    return base + ';'.join(funcs) + '})();'


def _generate_fake_css() -> str:
    """Генерирует ~8-12KB реалистичного CSS."""
    selectors = [
        '.container', '.header', '.nav', '.sidebar', '.content', '.footer',
        '.btn', '.btn-primary', '.card', '.modal', '.form-group', '.input',
        '.table', '.row', '.col', '.badge', '.alert', '.dropdown',
        '.toolbar', '.panel', '.list-item', '.avatar', '.spinner',
    ]
    properties = [
        'display:flex', 'padding:16px', 'margin:0 auto', 'color:#333',
        'background:#fff', 'border-radius:8px', 'font-size:14px',
        'box-shadow:0 2px 8px rgba(0,0,0,.1)', 'transition:all .2s',
        'line-height:1.5', 'font-weight:600', 'text-align:center',
        'overflow:hidden', 'position:relative', 'width:100%',
    ]
    rules = []
    for sel in selectors:
        n_props = random.randint(3, 8)
        props = ';'.join(random.sample(properties, min(n_props, len(properties))))
        rules.append(f'{sel}{{{props}}}')
        # Hover-состояния и media queries
        rules.append(f'{sel}:hover{{opacity:.8;cursor:pointer}}')
    rules.append('@media(max-width:768px){.container{padding:8px}.sidebar{display:none}}')
    return '\n'.join(rules)


@router.get("/cover/static/app.js", include_in_schema=False)
async def cover_js():
    """Фейковый JS-бандл — имитация SPA-приложения."""
    js_content = _generate_fake_js()
    return Response(
        content=js_content,
        media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=86400", "Server": "nginx/1.24.0"},
    )


@router.get("/cover/static/style.css", include_in_schema=False)
async def cover_css():
    """Фейковый CSS — имитация стилей веб-приложения."""
    css_content = _generate_fake_css()
    return Response(
        content=css_content,
        media_type="text/css",
        headers={"Cache-Control": "public, max-age=86400", "Server": "nginx/1.24.0"},
    )


@router.get("/cover/api/data", include_in_schema=False)
async def cover_api_data():
    """Фейковый API-ответ — имитация дашборда."""
    data = {
        "status": "ok",
        "timestamp": int(time.time()),
        "metrics": {
            "users": random.randint(100, 5000),
            "storage_gb": round(random.uniform(10, 500), 1),
            "sync_ops": random.randint(1000, 50000),
            "uptime": "99.97%",
        },
        "notifications": [],
        "version": "2.4.1",
    }
    return JSONResponse(data, headers={"Server": "nginx/1.24.0", "Cache-Control": "no-cache"})


@router.get("/cover/api/status", include_in_schema=False)
async def cover_api_status():
    """Фейковый health check."""
    return JSONResponse(
        {"status": "healthy", "region": "eu-west-1"},
        headers={"Server": "nginx/1.24.0"},
    )


@router.get("/cover", include_in_schema=False)
@router.get("/cover/{path:path}", include_in_schema=False)
async def cover_page(path: str = "", request: Request = None):
    """Serve realistic cover website pages."""
    key = f"/{path}" if path else "/"
    html = COVER_PAGES.get(key, COVER_PAGES["/"])

    response = HTMLResponse(html, headers={
        "Server": "nginx/1.24.0",
        "X-Powered-By": "Express",
        "Cache-Control": "public, max-age=3600",
    })

    # Knock sequence tracking
    from app.transport.knock import record_page_visit, is_knock_required
    if is_knock_required() and request:
        # Используем session cookie (не IP — через CDN IP меняется)
        import secrets as _s
        session_id = request.cookies.get("_ks") or _s.token_urlsafe(16)
        full_path = f"/cover/{path}" if path else "/cover"
        token = record_page_visit(session_id, full_path)
        if not request.cookies.get("_ks"):
            response.set_cookie("_ks", session_id, max_age=3600, httponly=False, path="/")
        if token:
            response.set_cookie("_vk", token, max_age=3600, httponly=False, path="/")

    return response


# ── Cover Traffic Generator ──────────────────────────────────────────────────

# Типичные размеры веб-ресурсов (байты) для имитации серфинга
_WEB_RESOURCE_SIZES = {
    "html":  (8_000,  25_000),
    "css":   (3_000,  15_000),
    "js":    (10_000, 80_000),
    "image": (5_000,  200_000),
    "font":  (20_000, 50_000),
    "api":   (100,    2_000),
}


class CoverTrafficGenerator:
    """
    Генератор фейкового трафика, имитирующего веб-серфинг.

    Паттерн реального серфинга:
      BURST  (1-3 сек): загрузка страницы -> 10-30 ресурсов (HTML, CSS, JS, img)
      PAUSE  (5-60 сек): пользователь читает страницу
      BURST  (1-3 сек): клик/переход -> ещё набор ресурсов

    Генератор создаёт тот же паттерн с рандомными данными,
    делая WS-трафик Vortex неотличимым от веб-серфинга.
    """

    def __init__(self):
        self._running = False
        self._tasks: list[asyncio.Task] = []

    async def start(self, ws_send_fn):
        """
        Запуск генерации покрывающего трафика.
        ws_send_fn: async callable для отправки байт через WebSocket
        """
        self._running = True
        self._tasks.append(asyncio.create_task(self._traffic_loop(ws_send_fn)))

    def stop(self):
        self._running = False
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()

    async def _traffic_loop(self, ws_send_fn):
        """Основной цикл: чередование burst и pause."""
        _keys = list(_WEB_RESOURCE_SIZES.keys())
        while self._running:
            try:
                # BURST: имитация загрузки страницы (5-20 «ресурсов» за 1-3 сек)
                # secrets используется вместо random — трафик должен быть непредсказуем для анализа
                num_resources = 5 + secrets.randbelow(16)          # [5, 20]
                for _ in range(num_resources):
                    resource_type = secrets.choice(_keys)
                    min_size, max_size = _WEB_RESOURCE_SIZES[resource_type]
                    cap  = min(max_size, 4096)
                    size = min_size + secrets.randbelow(cap - min_size + 1)

                    cover_data = os.urandom(size)
                    # Маркер cover-трафика (первый байт = 0x00)
                    tagged = b"\x00" + cover_data

                    try:
                        await ws_send_fn(tagged)
                    except Exception:
                        return

                    # Задержка между ресурсами (20-200мс)
                    await asyncio.sleep(0.02 + secrets.randbelow(181) / 1000)

                # PAUSE: имитация чтения страницы (5-45 секунд)
                pause = 5.0 + secrets.randbelow(40_001) / 1000
                await asyncio.sleep(pause)

            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.debug(f"Cover traffic error: {e}")
                await asyncio.sleep(5)

    @staticmethod
    def is_cover_traffic(data: bytes) -> bool:
        """Проверяет, является ли полученное сообщение cover-трафиком (начинается с 0x00)."""
        return len(data) > 0 and data[0] == 0x00

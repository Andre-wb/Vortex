# node_setup/wizard_routes.py
# ==============================================================================
# Все FastAPI-маршруты мастера настройки узла.
# ==============================================================================

from __future__ import annotations

import logging
import platform
import socket
import subprocess
import threading
from pathlib import Path

from fastapi import HTTPException
from fastapi.responses import HTMLResponse

from .models import SelfSignedRequest, ManualCertRequest, LetsEncryptRequest, NodeConfig, SSOConfig
from node_setup.ssl_manager import (
    check_cert_expiry,
    detect_available_methods,
    generate_letsencrypt,
    generate_self_signed,
    generate_with_mkcert,
    get_ca_install_instructions,
    use_manual_cert,
)
from ._app import wizard_app, CERT_DIR, _load_html, _setup_done
from .wizard_env import _read_env_dict, _write_env, _write_sso_env

logger = logging.getLogger(__name__)


def _shutdown_wizard():
    """Функция, вызываемая после завершения настройки: через 1.5 сек останавливает сервер."""
    import time
    time.sleep(1.5)
    _setup_done.set()
    # Читаем актуальное значение из _app напрямую
    from . import _app
    if _app._server_instance:
        _app._server_instance.should_exit = True


@wizard_app.get("/", response_class=HTMLResponse)
async def index():
    """Главная страница мастера (отдаёт HTML)."""
    return _load_html()


@wizard_app.get("/api/info")
async def system_info():
    """
    Возвращает системную информацию для отображения в интерфейсе:
    - hostname
    - ОС
    - локальные IP-адреса (определяются через сокет)
    - доступные методы генерации SSL
    - наличие существующих сертификатов
    - признак инициализации узла (NODE_INITIALIZED в .env)
    """
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Пытаемся подключиться к разным адресам, чтобы узнать реальный IP
        for t in ("192.168.1.1", "10.0.0.1", "8.8.8.8"):
            try:
                s.connect((t, 80))
                ip = s.getsockname()[0]
                if not ip.startswith("127."):
                    ips.append(ip)
                    break
            except Exception:
                pass
        s.close()
    except Exception:
        pass

    return {
        "hostname":   socket.gethostname(),
        "platform":   platform.system(),
        "local_ips":  ips,
        "ssl_methods": detect_available_methods(),
        "cert_exists": (CERT_DIR / "vortex.crt").exists(),
        "initialized": _read_env_dict().get("NODE_INITIALIZED") == "true",
    }


@wizard_app.get("/api/validate/port/{port}")
async def validate_port(port: int):
    """
    Проверяет, свободен ли указанный порт (попытка привязаться к 127.0.0.1).
    Возвращает ok: True/False и сообщение.
    """
    if not (1024 <= port <= 65535):
        return {"ok": False, "message": "Port must be between 1024 and 65535"}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        s.close()
        return {"ok": True, "message": f"Port {port} is available"}
    except OSError:
        return {"ok": False, "message": f"Port {port} is already in use"}


@wizard_app.post("/api/ssl/self-signed")
async def ssl_self_signed(body: SelfSignedRequest):
    """
    Генерирует самоподписанный сертификат с помощью ssl_manager.
    Возвращает пути к файлам и инструкцию по установке CA.
    """
    result = generate_self_signed(
        cert_dir       = CERT_DIR,
        hostname       = body.hostname or socket.gethostname(),
        org_name       = body.org_name,
        install_ca     = body.install_ca,
        admin_password = body.admin_password,
    )
    if not result.ok:
        raise HTTPException(500, result.message)

    return {
        "ok":          True,
        "cert":        result.cert,
        "key":         result.key,
        "ca":          result.ca,
        "trusted":     result.trusted,
        "message":     result.message,
    }


@wizard_app.post("/api/ssl/letsencrypt")
async def ssl_letsencrypt(body: LetsEncryptRequest):
    """
    Запрашивает сертификат Let's Encrypt через certbot.
    Требует указания домена и email.
    """
    if not body.domain:
        raise HTTPException(400, "Please specify a domain")
    result = generate_letsencrypt(
        cert_dir = CERT_DIR,
        domain   = body.domain,
        email    = body.email,
        staging  = body.staging,
    )
    if not result.ok:
        raise HTTPException(500, result.message)
    return {"ok": True, "cert": result.cert, "key": result.key, "message": result.message}


@wizard_app.post("/api/ssl/mkcert")
async def ssl_mkcert():
    """
    Генерирует сертификат через mkcert (локально доверенный).
    """
    result = generate_with_mkcert(CERT_DIR)
    if not result.ok:
        raise HTTPException(500, result.message)
    return {"ok": True, "cert": result.cert, "key": result.key,
            "trusted": result.trusted, "message": result.message}


@wizard_app.post("/api/ssl/manual")
async def ssl_manual(body: ManualCertRequest):
    """
    Принимает пути к существующим сертификатам (пользователь загрузил свои).
    Копирует их в рабочую директорию.
    """
    if not Path(body.cert_path).exists():
        raise HTTPException(400, f"Файл не найден: {body.cert_path}")
    if not Path(body.key_path).exists():
        raise HTTPException(400, f"Файл не найден: {body.key_path}")
    result = use_manual_cert(body.cert_path, body.key_path, CERT_DIR)
    if not result.ok:
        raise HTTPException(500, result.message)
    return {"ok": True, "message": result.message}


@wizard_app.get("/api/ssl/status")
async def ssl_status():
    """
    Проверяет наличие сертификата и его срок действия.
    Возвращает информацию для отображения в интерфейсе.
    """
    cert_path = CERT_DIR / "vortex.crt"
    if not cert_path.exists():
        return {"exists": False}
    info = check_cert_expiry(cert_path)
    return {"exists": True, **info}


@wizard_app.get("/api/ssl/skip")
async def ssl_skip():
    """Пропустить SSL — запускать по HTTP."""
    return {"ok": True, "message": "SSL skipped, node will run on HTTP"}


@wizard_app.get("/api/check-cloudflared")
async def check_cloudflared():
    """Check if cloudflared is installed."""
    try:
        subprocess.run(["cloudflared", "--version"], capture_output=True, timeout=5)
        return {"installed": True}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"installed": False}


@wizard_app.post("/api/sso/save")
async def save_sso(body: SSOConfig):
    """Сохраняет конфигурацию SSO/OAuth провайдеров в .env файл."""
    _write_sso_env(body)
    return {"ok": True, "message": "SSO configuration saved"}


@wizard_app.post("/api/config/save")
async def save_config(body: NodeConfig):
    """
    Сохраняет основную конфигурацию узла в .env файл.
    Генерирует секреты JWT и CSRF, если их ещё нет.
    """
    if not body.device_name.strip():
        raise HTTPException(400, "Please specify a device name")
    if not (1024 <= body.port <= 65535):
        raise HTTPException(400, "Invalid port")

    _write_env(body)
    return {"ok": True, "message": "Configuration saved"}


@wizard_app.post("/api/setup/complete")
async def complete_setup():
    """
    Завершает настройку:
    - Добавляет NODE_INITIALIZED=true в .env
    - Запускает фоновый поток для остановки сервера мастера
    - Возвращает URL, по которому будет доступен основной узел
    """
    env = _read_env_dict()
    lines = Path(".env").read_text(encoding="utf-8") if Path(".env").exists() else ""

    if "NODE_INITIALIZED=true" not in lines:
        with open(".env", "a", encoding="utf-8") as f:
            f.write("\nNODE_INITIALIZED=true\n")
    threading.Thread(target=_shutdown_wizard, daemon=True).start()

    port = int(env.get("PORT", "8000"))
    ssl = (CERT_DIR / "vortex.crt").exists()
    proto = "https" if ssl else "http"

    return {
        "ok": True,
        "message": "Setup complete! Launching node...",
        "url": f"{proto}://localhost:{port}",
    }

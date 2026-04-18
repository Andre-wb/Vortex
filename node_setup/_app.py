# node_setup/_app.py
# ==============================================================================
# Общий экземпляр FastAPI-приложения мастера и разделяемые константы.
# Вынесен в отдельный модуль, чтобы избежать циклических импортов между
# wizard.py, wizard_routes.py и wizard_env.py.
# ==============================================================================

from __future__ import annotations

import threading
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

# Файл с переменными окружения, который будет создан/дополнен
ENV_FILE = Path(".env")
# Директория для хранения сертификатов
CERT_DIR = Path("certs")

# FastAPI-приложение мастера (без документации, т.к. это внутренний интерфейс)
wizard_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# Подключаем статические файлы (CSS, JS для веб-интерфейса)
_STATIC_DIR = Path(__file__).parent / "static"
wizard_app.mount("/setup", StaticFiles(directory=str(_STATIC_DIR)), name="setup_static")

# Serve main app's static files (locales) for i18n in wizard
_MAIN_STATIC = Path(__file__).parent.parent / "static"
if _MAIN_STATIC.is_dir():
    wizard_app.mount("/static", StaticFiles(directory=str(_MAIN_STATIC)), name="main_static")

# Глобальная переменная для управления сервером
_server_instance: uvicorn.Server | None = None
# Событие, сигнализирующее о завершении настройки (остановка сервера)
_setup_done = threading.Event()


def _load_html() -> str:
    """Загружает HTML-шаблон страницы мастера, обрабатывая директивы включения.

    Поддерживает <!-- include: partials/name.html --> для вставки частичных шаблонов.
    """
    import re
    html_path = Path(__file__).parent / "templates" / "setup.html"
    if not html_path.exists():
        return "<h1>setup.html не найден</h1>"

    def _resolve(match: re.Match) -> str:
        partial = html_path.parent / match.group(1).strip()
        try:
            return partial.read_text(encoding="utf-8")
        except FileNotFoundError:
            return f"<!-- include not found: {partial.name} -->"

    content = html_path.read_text(encoding="utf-8")
    return re.sub(r'<!--\s*include:\s*(.+?)\s*-->', _resolve, content)

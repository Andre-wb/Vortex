# node_setup/wizard.py
# ==============================================================================
# Точка входа мастера настройки узла Vortex.
# Запускает временный веб-сервер (FastAPI) для проведения начальной конфигурации:
#   - проверка системной информации
#   - валидация портов
#   - создание SSL-сертификатов (самоподписанные, mkcert, Let's Encrypt, ручные)
#   - сохранение параметров в .env
#   - завершение мастера и запуск основного приложения
# ==============================================================================

from __future__ import annotations

import threading

import uvicorn

# Импортируем приложение и разделяемое состояние из _app
from ._app import wizard_app, _setup_done

# Регистрация маршрутов — побочный эффект импорта (декораторы @wizard_app)
from . import wizard_routes  # noqa: F401

# Реэкспорт для обратной совместимости (from node_setup.wizard import run_wizard)
__all__ = ["wizard_app", "run_wizard"]


def run_wizard(host: str = "127.0.0.1", port: int = 7979) -> None:
    """
    Запускает сервер мастера на указанном хосте и порту.
    Функция блокируется до тех пор, пока не будет вызвано _setup_done.
    """
    from . import _app

    config = uvicorn.Config(
        app      = wizard_app,
        host     = host,
        port     = port,
        log_level= "warning",
        access_log = False,
    )
    _app._server_instance = uvicorn.Server(config)

    thread = threading.Thread(target=_app._server_instance.run, daemon=True)
    thread.start()

    try:
        _setup_done.wait()  # ждём сигнала завершения
    except KeyboardInterrupt:
        pass
    finally:
        if _app._server_instance:
            _app._server_instance.should_exit = True
        thread.join(timeout=3)

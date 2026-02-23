#!/usr/bin/env python
"""
Скрипт для запуска Vortex Chat сервера
Использование:
    python run.py          # запуск с uvicorn
    python run.py --dev    # запуск с fastapi dev (режим разработки)
"""

import os
import sys
import argparse
import subprocess
import webbrowser
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Запуск Vortex Chat сервера")
    parser.add_argument("--dev", action="store_true", help="Запуск в режиме разработки с fastapi dev")
    parser.add_argument("--port", type=int, default=8000, help="Порт для запуска (по умолчанию: 8000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Хост для запуска (по умолчанию: 0.0.0.0)")
    parser.add_argument("--no-browser", action="store_true", help="Не открывать браузер автоматически")

    args = parser.parse_args()

    # Проверяем наличие виртуального окружения
    in_venv = sys.prefix != sys.base_prefix
    if not in_venv:
        print("⚠️  Предупреждение: Виртуальное окружение не активировано!")
        print("   Рекомендуется активировать venv перед запуском:")
        print("   source venv/bin/activate  # Linux/Mac")
        print("   venv\\Scripts\\activate     # Windows")
        print()

    # Проверяем наличие собранного Rust модуля
    try:
        import vortex_chat
        print(f"✅ Rust модуль загружен (версия: {vortex_chat.VERSION})")
    except ImportError:
        print("❌ Rust модуль не найден! Собираем...")
        try:
            subprocess.run(["maturin", "develop", "--release"], check=True)
            print("✅ Rust модуль успешно собран")
        except subprocess.CalledProcessError:
            print("❌ Ошибка сборки Rust модуля")
            print("   Убедитесь, что установлен maturin: pip install maturin")
            sys.exit(1)
        except FileNotFoundError:
            print("❌ maturin не найден! Установите: pip install maturin")
            sys.exit(1)

    # Открываем браузер
    if not args.no_browser:
        url = f"http://localhost:{args.port}"
        print(f"🌐 Открываем браузер: {url}")
        webbrowser.open(url)

    # Запускаем сервер
    if args.dev:
        print(f"🚀 Запуск в режиме разработки (fastapi dev) на {args.host}:{args.port}")
        cmd = [
            "fastapi", "dev", "app/main.py",
            "--port", str(args.port),
            "--host", args.host
        ]
    else:
        print(f"🚀 Запуск в production режиме (uvicorn) на {args.host}:{args.port}")
        cmd = [
            "uvicorn", "app.main:app",
            "--host", args.host,
            "--port", str(args.port),
            "--reload"  # Добавляем reload для разработки
        ]

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n👋 Сервер остановлен")
    except FileNotFoundError:
        if args.dev:
            print("❌ fastapi не найден! Установите: pip install fastapi[standard]")
        else:
            print("❌ uvicorn не найден! Установите: pip install uvicorn[standard]")
        sys.exit(1)

if __name__ == "__main__":
    main()
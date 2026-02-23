from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
import asyncio
import json
import time
import vortex_chat
from pathlib import Path

app = FastAPI()

# Подключаем статические файлы (HTML, JS)
BASE_DIR = Path(__file__).resolve().parent          # vortex-server/
STATIC_DIR = BASE_DIR.parent / "static"             # Vortex/static/

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
# Хранилище активных подключений
active_connections = {}
chat_stats = vortex_chat.ChatStats()  # Rust класс!

# Ключ шифрования (в реальном проекте должен быть уникальным для каждого чата)
ENCRYPTION_KEY = 42

@app.get("/")
async def root():
    return {"message": "P2P Chat Server", "status": "running"}

@app.get("/stats")
async def get_stats():
    """Статистика работы Rust-функций"""
    # Тест скорости Rust vs Python
    test_message = b"x" * 1000

    # Python хэш (для сравнения)
    import hashlib
    start = time.time()
    for _ in range(10000):
        hashlib.sha256(test_message).hexdigest()
    py_time = time.time() - start

    # Rust хэш
    start = time.time()
    for _ in range(10000):
        vortex_chat.hash_message(test_message)
    rust_time = time.time() - start

    return {
        "chat_stats": chat_stats.get_stats(),
        "benchmark": {
            "python_hash_10000": f"{py_time:.3f} сек",
            "rust_hash_10000": f"{rust_time:.3f} сек",
            "speedup": f"{py_time/rust_time:.1f}x"
        },
        "version": vortex_chat.VERSION
    }

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await websocket.accept()
    active_connections[client_id] = websocket
    print(f"✅ {client_id} подключился")

    # Отправляем приветствие
    await websocket.send_json({
        "type": "system",
        "message": f"👋 Привет, {client_id}! Чат защищен Rust-шифрованием"
    })

    # Уведомляем всех о новом пользователе
    for conn_id, conn in active_connections.items():
        if conn_id != client_id:
            await conn.send_json({
                "type": "system",
                "message": f"📢 {client_id} присоединился к чату"
            })

    try:
        while True:
            # Получаем сообщение
            data = await websocket.receive_text()
            message_data = json.loads(data)

            if message_data["type"] == "message":
                text = message_data["text"]

                # 1. Шифруем сообщение (Rust)
                encrypted = vortex_chat.encrypt_message(
                    text.encode(),
                    ENCRYPTION_KEY
                )

                # 2. Хэшируем для проверки (Rust)
                msg_hash = vortex_chat.hash_message(encrypted)

                # 3. Обновляем статистику (Rust)
                chat_stats.add_message(len(text))

                print(f"💬 {client_id}: {text}")
                print(f"🔒 Зашифровано: {len(encrypted)} байт")
                print(f"🔑 Хэш: {msg_hash[:16]}...")

                # Рассылаем всем КРОМЕ отправителя
                for conn_id, conn in active_connections.items():
                    if conn_id != client_id:
                        # Дешифруем для получателя (Rust)
                        decrypted = vortex_chat.decrypt_message(
                            encrypted,
                            ENCRYPTION_KEY
                        )

                        await conn.send_json({
                            "type": "message",
                            "from": client_id,
                            "text": decrypted.decode(),
                            "hash": msg_hash[:8],
                            "encrypted_size": len(encrypted)
                        })

                # Подтверждение отправителю
                await websocket.send_json({
                    "type": "delivery",
                    "status": "sent",
                    "hash": msg_hash[:8]
                })

    except Exception as e:
        print(f"❌ {client_id} отключился: {e}")
    finally:
        del active_connections[client_id]
        # Уведомляем всех об уходе
        for conn in active_connections.values():
            await conn.send_json({
                "type": "system",
                "message": f"👋 {client_id} покинул чат"
            })

if __name__ == "__main__":
    import uvicorn
    print("🚀 Чат-сервер запускается...")
    print(f"🔐 Ключ шифрования: {ENCRYPTION_KEY}")
    print(f"⚡ Rust версия: {vortex_chat.VERSION}")
    uvicorn.run(app, host="0.0.0.0", port=8000)
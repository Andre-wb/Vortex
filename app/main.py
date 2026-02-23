from app import create_app
import uvicorn

app = create_app()

if __name__ == "__main__":
    print("🚀 Чат-сервер запускается...")
    print(f"🔐 Ключ шифрования: 42")
    import vortex_chat
    print(f"⚡ Rust версия: {vortex_chat.VERSION}")
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
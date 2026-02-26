from app import create_app
import uvicorn

app = create_app()

if __name__ == "__main__":
    print("🚀 Chat-server running...")
    print(f"🔐 Key: 42")
    import vortex_chat
    print(f"⚡ Rust version: {vortex_chat.VERSION}")
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
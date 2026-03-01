from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import vortex_chat
from app.routes import web, websocket, web_router, websocket_router

def create_app() -> FastAPI:
    app = FastAPI(title="Vortex Chat", version=vortex_chat.VERSION)

    # Statics
    static_path = Path(__file__).parent.parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

    # Routes
    app.include_router(web.router)
    app.include_router(websocket.router)
    app.include_router(web_router)
    app.include_router(websocket_router)

    return app
"""Internal FastAPI app that powers the Wizard UI.

Serves two SPAs:
    /           — setup wizard (when mode=="setup")
    /           — admin dashboard (when mode=="admin")

Plus a small set of /api/wiz/* endpoints for data the UI needs. Every
endpoint is loopback-only (server binds 127.0.0.1) — no network exposure.
"""
from __future__ import annotations

import contextlib
import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import VERSION
from .api import setup_api, admin_api

logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).parent / "web"


def build_app(mode: str, env_file: "Path | None" = None) -> FastAPI:
    if mode not in ("setup", "admin"):
        raise ValueError(f"invalid mode: {mode!r}")

    app = FastAPI(
        title="Vortex Wizard",
        version=VERSION,
        docs_url=None, redoc_url=None, openapi_url=None,
    )
    app.state.mode = mode
    # Where to read/write the Vortex env file — set once here so both
    # setup_api and admin_api pick it up via request.app.state.env_file.
    app.state.env_file = (env_file or Path(".env")).expanduser().resolve()
    logger.info("Wizard env file: %s", app.state.env_file)

    # Both APIs are always mounted so either SPA can call either endpoint
    # during its lifetime (e.g. an admin user reconfiguring, or a setup flow
    # reading the current system before writing).
    app.include_router(setup_api.router)
    app.include_router(admin_api.router)

    # Shared static assets (common.css, fonts, icons, locales)
    assets_dir = WEB_DIR / "assets"
    if assets_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(assets_dir)), name="static")

    locales_dir = WEB_DIR / "locales"
    if locales_dir.is_dir():
        app.mount("/locales", StaticFiles(directory=str(locales_dir)), name="locales")

    def _current_mode() -> str:
        """Pick mode per-request.

        If the startup mode was 'setup' and the env file now has
        NODE_INITIALIZED=true, switch to 'admin' without a restart.
        Otherwise stay with the startup choice.
        """
        if mode == "setup":
            ef = app.state.env_file
            if ef.is_file():
                try:
                    for line in ef.read_text(encoding="utf-8").splitlines():
                        s = line.strip()
                        if s.startswith("NODE_INITIALIZED="):
                            if s.split("=", 1)[1].strip().lower() in ("true", "1", "yes"):
                                return "admin"
                except OSError:
                    pass
        return mode

    @app.get("/mode", include_in_schema=False)
    async def _mode_info():
        return {"mode": _current_mode(), "version": VERSION}

    @app.get("/{path:path}", include_in_schema=False)
    async def _spa(path: str):
        """SPA catch-all: serve static files from the *current* mode's dir."""
        cur = _current_mode()
        spa_dir = WEB_DIR / cur
        index_path = spa_dir / "index.html"
        target = spa_dir / path
        if path and target.is_file():
            return FileResponse(target)
        return FileResponse(index_path)

    return app

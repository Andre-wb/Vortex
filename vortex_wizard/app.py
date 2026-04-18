"""Vortex Wizard entry point.

Launches a local FastAPI server on an ephemeral port and opens a native
webview window pointing at it. Closes the server when the window closes.

Mode selection:
    * First launch (.env missing)   → setup UI
    * Subsequent launches           → admin dashboard
    * ``--mode`` flag overrides
"""
from __future__ import annotations

import argparse
import logging
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from . import VERSION


logger = logging.getLogger("vortex_wizard")


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _auto_mode(env_file: Path) -> str:
    """Admin only when the env file is present AND marks setup as complete.

    The presence of a file alone isn't enough — it may be a leftover from a
    previous test run or a partial write. We look for the explicit
    ``NODE_INITIALIZED=true`` marker the setup handler writes on success.
    """
    if not env_file.is_file():
        return "setup"
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("NODE_INITIALIZED="):
                val = line.split("=", 1)[1].strip().lower()
                if val in ("true", "1", "yes"):
                    return "admin"
    except OSError:
        pass
    return "setup"


def _default_env_file() -> Path:
    """Pick a writable default location for the Vortex env file.

    When running from a PyInstaller .app bundle the CWD is typically "/" or
    "/Applications", which is not writable by the current user. We store
    per-user config under the platform-standard directory instead:

        macOS   : ~/Library/Application Support/Vortex/.env
        Linux   : ~/.config/vortex/.env
        Windows : %APPDATA%\\Vortex\\.env

    When running from a dev checkout (not frozen) we keep the old behavior
    of using ``./.env`` relative to CWD so existing workflows still work.
    """
    if not getattr(sys, "frozen", False):
        return Path(".env")
    home = Path.home()
    if sys.platform == "darwin":
        base = home / "Library" / "Application Support" / "Vortex"
    elif sys.platform.startswith("win"):
        import os
        base = Path(os.environ.get("APPDATA") or home) / "Vortex"
    else:
        import os
        base = Path(os.environ.get("XDG_CONFIG_HOME") or (home / ".config")) / "vortex"
    base.mkdir(parents=True, exist_ok=True)
    return base / ".env"


def _start_server(mode: str, host: str, port: int, env_file: Path) -> None:
    """Uvicorn in the main thread, blocks until shutdown."""
    import uvicorn
    from .server import build_app

    app = build_app(mode=mode, env_file=env_file)
    uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)


def _open_window(url: str, title: str) -> None:
    """Open a native webview window pointing at ``url``.

    Uses pywebview when available; falls back to opening the user's default
    browser otherwise (useful for headless servers or CI).

    On macOS the grey title bar is made transparent so the dark content
    extends to the very top (Linear/Figma/Notion style). Traffic lights
    stay in place; the title text is hidden.
    """
    try:
        import webview  # pywebview
    except ImportError:
        logger.info("pywebview not installed — opening browser instead")
        import webbrowser
        webbrowser.open(url)
        return

    window = webview.create_window(
        title=title,
        url=url,
        width=1180,
        height=820,
        min_size=(900, 620),
        background_color="#000000",
    )

    def _polish_chrome():
        _apply_macos_transparent_titlebar(window)

    webview.start(
        _polish_chrome,
        debug=os.getenv("VORTEX_WIZARD_DEBUG") == "1",
        private_mode=True,  # No persistent storage — zero metadata residue
    )


def _apply_macos_transparent_titlebar(window) -> None:
    """Hide the grey title bar on macOS, keep the traffic lights.

    Runs once pywebview's Cocoa backend has created the NSWindow. Uses
    Apple's public API — ``titlebarAppearsTransparent`` +
    ``NSWindowStyleMaskFullSizeContentView`` — so HTML paints behind where
    the bar used to be. The window is still resizable/minimizable/closeable
    via the traffic light buttons.
    """
    if sys.platform != "darwin":
        return
    try:
        import AppKit  # PyObjC, shipped by pywebview on macOS
    except ImportError:
        return

    ns_window = getattr(window, "native", None)
    if ns_window is None:
        return

    try:
        ns_window.setTitlebarAppearsTransparent_(True)
        ns_window.setTitleVisibility_(AppKit.NSWindowTitleHidden)
        # NSWindowStyleMaskFullSizeContentView == 1 << 15
        ns_window.setStyleMask_(ns_window.styleMask() | (1 << 15))
        ns_window.setMovableByWindowBackground_(True)
    except Exception as e:
        logger.debug("macOS chrome tweak failed: %s", e)


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    ap = argparse.ArgumentParser(
        prog="vortex-wizard",
        description="Vortex node setup + admin dashboard (all-local, zero telemetry)",
    )
    ap.add_argument(
        "--mode", choices=("auto", "setup", "admin"), default="auto",
        help="Force a specific UI mode (default: auto)",
    )
    ap.add_argument(
        "--host", default="127.0.0.1",
        help="Bind host (default: 127.0.0.1 — loopback only)",
    )
    ap.add_argument(
        "--port", type=int, default=None,
        help="Bind port (default: random free port)",
    )
    ap.add_argument(
        "--no-window", action="store_true",
        help="Don't launch the webview — serve the API on stdout only",
    )
    ap.add_argument(
        "--env-file", type=Path, default=None,
        help="Vortex env file to read/write (default: per-user config dir)",
    )
    args = ap.parse_args(argv)

    env_file = args.env_file or _default_env_file()

    mode = args.mode if args.mode != "auto" else _auto_mode(env_file)
    port = args.port or _pick_free_port()
    url = f"http://{args.host}:{port}"
    title = f"Vortex Wizard — {mode.capitalize()} · v{VERSION}"

    logger.info("Starting in %s mode on %s (env=%s)", mode, url, env_file)

    # Run uvicorn in a background thread so pywebview's event loop can own
    # the main thread (required on macOS for AppKit).
    server_thread = threading.Thread(
        target=_start_server, args=(mode, args.host, port, env_file), daemon=True,
    )
    server_thread.start()

    # Wait until the server is actually listening.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((args.host, port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.1)
    else:
        logger.error("Server did not start on %s", url)
        return 1

    if args.no_window:
        logger.info("Running headless — visit %s manually", url)
        try:
            server_thread.join()
        except KeyboardInterrupt:
            pass
        return 0

    _open_window(url, title)
    # After the window closes pywebview returns; let the daemon thread exit.
    return 0

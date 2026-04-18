"""Vortex Wizard — standalone desktop app for node operators.

Two modes in one binary:

    Setup mode (first launch):
        Interactive wizard that generates .env, SSL certs, JWT secrets,
        and (optionally) seals the node on-chain via the Solana registry.

    Admin mode (every subsequent launch):
        Seven-panel dashboard showing integrity, node identity, controller
        connection, peer verification, live traffic, certs/keys, logs.

Both modes share one internal FastAPI process on localhost; the UI is
rendered by a native system webview (pywebview) so there's no browser
dependency and no telemetry leaves the machine.

Entry point:

    python -m vortex_wizard                 # auto-detects mode
    python -m vortex_wizard --mode setup    # force setup
    python -m vortex_wizard --mode admin    # force admin
"""

VERSION = "0.1.0"

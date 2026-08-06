"""
app/bots/bot_api.py — Thin re-export for backward compatibility.

The bot subsystem has been split into:
  - bot_shared.py      : router, auth dependency, queues, schemas, constants
  - bot_crud.py        : bot management endpoints (CRUD, tokens, room membership)
  - bot_messaging.py   : bot HTTP API, WebSocket, and notify_bots_in_room helper
  - bot_marketplace.py : marketplace browsing, reviews, install

All sub-modules register their routes on the shared router imported from
bot_shared.py. Importing `router` from this file still works as before.
"""

# Import sub-modules so their @router decorators execute and register routes
import app.bots.bot_crud
import app.bots.bot_marketplace
import app.bots.bot_messaging  # noqa: F401 — registers messaging routes

# Re-export public helpers used by other parts of the codebase (e.g. chat.py)
from app.bots.bot_messaging import notify_bots_in_room  # noqa: F401
from app.bots.bot_shared import (
    enqueue_bot_update,  # noqa: F401
    router,  # noqa: F401 — the single shared router
)

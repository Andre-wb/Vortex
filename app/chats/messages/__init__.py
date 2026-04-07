"""
app/chats/messages/ — WebSocket чат и обработка сообщений.

Модули:
  _router.py    — Общий APIRouter, утилиты (utc_iso, parse_client_ts, ...)
  core.py       — WebSocket endpoint, cleanup_expired_messages
  messages.py   — Отправка, редактирование, удаление сообщений
  actions.py    — Реакции, пины, форвард
  history.py    — Загрузка истории сообщений
  keys.py       — E2E ключи: доставка, запросы, ответы
  flood.py      — Flood detection: автомут/автобан
  moderation.py — Мут/бан участников через чат
  polls.py      — Опросы: создание, голосование
  push.py       — Web Push уведомления
  schedule.py   — Отложенные сообщения
  ws_signal.py  — WebRTC сигнальные события
  files.py      — Загрузка файлов через чат
"""
from app.chats.messages._router import router  # noqa: F401
from app.chats.messages.core import cleanup_expired_messages  # noqa: F401

# Регистрируем все sub-роутеры на общем router
import app.chats.messages.core        # noqa: F401
import app.chats.messages.messages    # noqa: F401
import app.chats.messages.actions     # noqa: F401
import app.chats.messages.history     # noqa: F401
import app.chats.messages.keys        # noqa: F401
import app.chats.messages.moderation  # noqa: F401
import app.chats.messages.polls       # noqa: F401
import app.chats.messages.push        # noqa: F401
import app.chats.messages.schedule    # noqa: F401
import app.chats.messages.ws_signal   # noqa: F401
import app.chats.messages.files       # noqa: F401
import app.chats.messages.rest        # noqa: F401

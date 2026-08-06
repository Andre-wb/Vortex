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
import app.chats.messages.actions

# Регистрируем все sub-роутеры на общем router
import app.chats.messages.core
import app.chats.messages.files
import app.chats.messages.history
import app.chats.messages.keys
import app.chats.messages.messages
import app.chats.messages.moderation
import app.chats.messages.polls
import app.chats.messages.push
import app.chats.messages.rest
import app.chats.messages.schedule
import app.chats.messages.ws_signal  # noqa: F401
from app.chats.messages._router import router  # noqa: F401
from app.chats.messages.core import cleanup_expired_messages  # noqa: F401

"""
app/chats/rooms/ — Управление комнатами.

Модули:
  helpers.py  — Общий router, Pydantic-схемы, вспомогательные функции
  crud.py     — CRUD: создание, обновление, удаление, покидание
  members.py  — Участники: список, кик, роли, мут, бан
  keys.py     — Ключи: вступление, предоставление, key-bundle, ротация
  theme.py    — Темы комнат: установка, сброс, принятие DM-тем
"""
# Импорт подмодулей регистрирует @router.* декораторы на общем router
import app.chats.rooms.crud
import app.chats.rooms.keys
import app.chats.rooms.members
import app.chats.rooms.public_keys
import app.chats.rooms.theme  # noqa: F401
from app.chats.rooms.helpers import _room_dict, router  # noqa: F401

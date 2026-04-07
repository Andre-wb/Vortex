"""
app/chats/chat.py — Шим для обратной совместимости.

Содержимое перенесено в app/chats/messages/.
Используйте: from app.chats.messages import router, cleanup_expired_messages
"""
from app.chats.messages import router, cleanup_expired_messages  # noqa: F401

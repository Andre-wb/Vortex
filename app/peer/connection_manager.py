"""
app/peer/connection_manager.py — WebSocket менеджер с разделением по комнатам.

Добавлено:
- Глобальный кэш seen_ids для дедупликации сообщений (критерий 5.1)
- TokenBucket rate limiter для защиты ретранслятора от перегрузки (критерий 5.2)
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Token Bucket — ограничение нагрузки на ретранслятор
# ══════════════════════════════════════════════════════════════════════════════

class TokenBucket:
    """
    Алгоритм Token Bucket для ограничения скорости сообщений.

    Параметры:
        capacity   — максимальное число токенов (всплески).
        rate       — скорость пополнения (токенов/сек).

    Пример: capacity=20, rate=5 разрешает всплески до 20 сообщений,
    но в среднем не более 5 в секунду.
    """

    __slots__ = ("capacity", "rate", "_tokens", "_last_ts")

    def __init__(self, capacity: float = 20.0, rate: float = 5.0):
        self.capacity  = capacity
        self.rate      = rate
        self._tokens   = capacity
        self._last_ts  = time.monotonic()

    def consume(self, tokens: float = 1.0) -> bool:
        """
        Пытается потребить `tokens` токенов.
        Возвращает True если токенов достаточно, False — если лимит исчерпан.
        """
        now   = time.monotonic()
        delta = now - self._last_ts
        self._last_ts = now
        self._tokens  = min(self.capacity, self._tokens + delta * self.rate)
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False


# ══════════════════════════════════════════════════════════════════════════════
# Глобальный кэш дедупликации сообщений
# ══════════════════════════════════════════════════════════════════════════════

class MessageDeduplicator:
    """
    LRU-подобный кэш уже обработанных msg_id.

    Хранит последние `max_size` идентификаторов.
    При превышении лимита удаляет самые старые записи (FIFO).
    TTL — дополнительная защита от устаревших повторов.
    """

    def __init__(self, max_size: int = 10_000, ttl_sec: float = 300.0):
        self._max_size = max_size
        self._ttl      = ttl_sec
        self._seen:    dict[str, float] = {}   # msg_id → timestamp
        self._order:   deque[str]       = deque()
        self._lock     = asyncio.Lock()

    async def is_duplicate(self, msg_id: str) -> bool:
        """
        Возвращает True если msg_id уже обрабатывался, иначе регистрирует его и возвращает False.
        """
        async with self._lock:
            now = time.monotonic()

            # Проверяем TTL: чистим записи старше TTL
            while self._order and (now - self._seen.get(self._order[0], now)) > self._ttl:
                old = self._order.popleft()
                self._seen.pop(old, None)

            if msg_id in self._seen:
                return True

            # Добавляем
            self._seen[msg_id] = now
            self._order.append(msg_id)

            # Обрезаем по размеру
            while len(self._seen) > self._max_size:
                old = self._order.popleft()
                self._seen.pop(old, None)

            return False

    def seen_count(self) -> int:
        return len(self._seen)


# Глобальный экземпляр дедупликатора для всего приложения
deduplicator = MessageDeduplicator(max_size=10_000, ttl_sec=300.0)


# ══════════════════════════════════════════════════════════════════════════════
# ConnectedUser
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ConnectedUser:
    """
    Хранит информацию о подключённом пользователе в комнате.

    Дополнения:
        rate_limiter — индивидуальный Token Bucket для защиты от флуда.
    """
    user_id:      int
    username:     str
    display_name: str
    avatar_emoji: str
    websocket:    WebSocket
    room_id:      int
    connected_at: datetime    = field(default_factory=lambda: datetime.now(timezone.utc))
    is_typing:    bool        = False
    rate_limiter: TokenBucket = field(default_factory=lambda: TokenBucket(capacity=30, rate=10))


# ══════════════════════════════════════════════════════════════════════════════
# Pending Delivery Queue — серверная очередь недоставленных сообщений
# ══════════════════════════════════════════════════════════════════════════════

class PendingDeliveryQueue:
    """
    In-memory очередь сообщений для офлайн-пользователей.

    Когда broadcast не может доставить сообщение (пользователь не в комнате),
    оно сохраняется здесь. При реконнекте — flush_pending() отдаёт накопленные.

    Лимиты:
    - max_per_user_room: 1000 сообщений на (user_id, room_id) — предотвращает OOM
    - ttl_sec: 604800 (7 дней) — старые сообщения удаляются
    """

    def __init__(self, max_per_user_room: int = 1000, ttl_sec: float = 604800.0):
        self._max    = max_per_user_room
        self._ttl    = ttl_sec
        # (room_id, user_id) → deque[(timestamp, payload)]
        self._queues: dict[tuple[int, int], deque] = defaultdict(deque)
        self._lock   = asyncio.Lock()

    async def enqueue(self, room_id: int, user_id: int, payload: dict) -> None:
        """Добавить сообщение в очередь для офлайн-пользователя."""
        async with self._lock:
            key = (room_id, user_id)
            q = self._queues[key]
            q.append((time.monotonic(), payload))
            # Обрезаем по лимиту — удаляем самые старые
            while len(q) > self._max:
                q.popleft()

    async def flush_pending(self, room_id: int, user_id: int, ws: WebSocket) -> int:
        """Отправить все накопленные сообщения пользователю. Возвращает количество."""
        async with self._lock:
            key = (room_id, user_id)
            q = self._queues.pop(key, deque())

        if not q:
            return 0

        now = time.monotonic()
        sent = 0
        for ts, payload in q:
            # Пропускаем устаревшие (> TTL)
            if now - ts > self._ttl:
                continue
            try:
                payload["_pending"] = True  # маркер для клиента
                await ws.send_json(payload)
                sent += 1
            except Exception:
                break
        return sent

    async def cleanup(self) -> int:
        """Удалить устаревшие записи. Вызывать периодически."""
        async with self._lock:
            now = time.monotonic()
            removed = 0
            empty_keys = []
            for key, q in self._queues.items():
                while q and (now - q[0][0]) > self._ttl:
                    q.popleft()
                    removed += 1
                if not q:
                    empty_keys.append(key)
            for key in empty_keys:
                del self._queues[key]
            return removed

    def stats(self) -> dict:
        return {
            "queues": len(self._queues),
            "total_pending": sum(len(q) for q in self._queues.values()),
        }


# Глобальный экземпляр pending delivery queue
pending_queue = PendingDeliveryQueue()


class PendingNotificationQueue:
    """
    Очередь уведомлений для пользователей, у которых нет активного notification WS.
    Flush-ится при подключении к /ws/notifications.
    """

    def __init__(self, max_per_user: int = 50, ttl_sec: float = 300.0):
        self._max  = max_per_user
        self._ttl  = ttl_sec
        self._queues: dict[int, deque] = defaultdict(deque)
        self._lock   = asyncio.Lock()

    async def enqueue(self, user_id: int, payload: dict) -> None:
        async with self._lock:
            q = self._queues[user_id]
            q.append((time.monotonic(), payload))
            while len(q) > self._max:
                q.popleft()

    async def flush(self, user_id: int, ws: WebSocket) -> int:
        async with self._lock:
            q = self._queues.pop(user_id, deque())
        if not q:
            return 0
        now = time.monotonic()
        sent = 0
        for ts, payload in q:
            if now - ts > self._ttl:
                continue
            try:
                payload["_pending"] = True
                await ws.send_json(payload)
                sent += 1
            except Exception:
                break
        return sent

    def stats(self) -> dict:
        return {
            "queues": len(self._queues),
            "total": sum(len(q) for q in self._queues.values()),
        }


pending_notifications = PendingNotificationQueue()


# ══════════════════════════════════════════════════════════════════════════════
# ConnectionManager
# ══════════════════════════════════════════════════════════════════════════════

class ConnectionManager:
    """
    Менеджер WebSocket-соединений с поддержкой комнат.

    Расширения по сравнению с исходной версией:
    1. Проверка дедупликации сообщений через глобальный MessageDeduplicator.
    2. Token Bucket rate limiting на пользователя для broadcast.
    3. Метод check_rate_limit() для проверки перед обработкой входящего сообщения.
    """

    def __init__(self):
        self._rooms:      dict[int, dict[int, ConnectedUser]] = defaultdict(dict)
        self._global_ws:  dict[int, WebSocket] = {}
        self._sse_queues: dict[str, asyncio.Queue] = {}
        self._lock        = asyncio.Lock()

    async def connect(
            self,
            room_id:      int,
            user_id:      int,
            username:     str,
            display_name: str,
            avatar_emoji: str,
            ws:           WebSocket,
    ) -> None:
        await ws.accept()
        async with self._lock:
            self._rooms[room_id][user_id] = ConnectedUser(
                user_id      = user_id,
                username     = username,
                display_name = display_name,
                avatar_emoji = avatar_emoji,
                websocket    = ws,
                room_id      = room_id,
            )
        logger.debug("WS+ connection (sanitized)")

        # Flush pending messages accumulated while user was offline
        flushed = await pending_queue.flush_pending(room_id, user_id, ws)
        if flushed > 0:
            logger.debug(f"Flushed {flushed} pending messages (sanitized)")

        # BMP mode: suppress user_joined broadcast (zero metadata leakage)
        # Presence is derived from BMP activity, not WS connections

    async def disconnect(self, room_id: int, user_id: int) -> None:
        async with self._lock:
            user = self._rooms[room_id].pop(user_id, None)
            if not self._rooms[room_id]:
                del self._rooms[room_id]

        if user:
            logger.debug("WS- connection (sanitized)")
            # BMP mode: suppress user_left broadcast (zero metadata leakage)

    # Message types that are system/control (always go via WS)
    _WS_ONLY_TYPES = frozenset({
        "room_deleted", "key_rotated", "kicked", "room_updated", "ack", "error",
        "pong", "system", "waiting_for_key", "node_pubkey", "room_key",
        "key_request", "key_response", "online",
    })

    # Content types that go via BMP (zero metadata leakage)
    # Content types: ALL go through BMP (zero metadata leakage)
    # Covers: rooms, groups, channels, DMs, federated rooms, spaces
    _BMP_TYPES = frozenset({
        "message", "thread_message", "message_edited", "message_deleted",
        "reaction", "messages_read", "message_pinned", "typing",
        "file_sending", "stop_file_sending", "screenshot_taken",
        "signal", "poll", "poll_update", "voice_update", "voice_state",
        "file", "forward", "thread_update",
        "stream_scheduled", "stream_update", "stream_state",
        "auto_delete_changed", "slow_mode_changed",
        "channel_feed", "space_update",
        "group_call_invite", "group_call_update",
        "notification", "new_dm", "incoming_call",
    })

    async def broadcast_to_room(
            self,
            room_id: int,
            payload: dict[str, Any],
            exclude: int | None = None,
            member_ids: list[int] | None = None,
    ) -> None:
        msg_type = payload.get("type", "")

        # BMP delivery for content messages
        from app.config import Config
        if Config.BMP_DELIVERY_ENABLED and msg_type in self._BMP_TYPES:
            try:
                from app.transport.blind_mailbox import deposit_envelope
                import json
                await deposit_envelope(room_id, json.dumps(payload))
            except Exception as e:
                logger.debug("BMP deposit failed (sanitized)")

            # Enqueue pending for offline users (messages only)
            if member_ids and msg_type in ("message", "thread_message"):
                online = set(self._rooms.get(room_id, {}).keys())
                for uid in member_ids:
                    if uid not in online and uid != exclude:
                        await pending_queue.enqueue(room_id, uid, payload)

            # Edit/delete/reaction must also go via WS for instant UI update
            # (BMP polling has latency; these actions need immediate feedback)
            _ws_also = {"message_edited", "message_deleted", "reaction",
                        "message_pinned", "typing", "messages_read"}
            if msg_type not in _ws_also:
                return  # BMP-only for content messages

        # System/control messages: send via WS as before
        dead = []
        delivered_uids: set[int] = set()
        for uid, conn in dict(self._rooms.get(room_id, {})).items():
            if uid == exclude:
                delivered_uids.add(uid)
                continue
            try:
                await conn.websocket.send_text(self._pad_ws_frame(payload))
                delivered_uids.add(uid)
            except Exception as e:
                logger.debug("Broadcast: dead WS for user %s room %s: %s", uid, room_id, e)
                dead.append(uid)

        for uid in dead:
            await self.disconnect(room_id, uid)

        # SSE fallback for system messages
        if self._sse_queues:
            prefix = f"sse:{room_id}:"
            for key, queue in list(self._sse_queues.items()):
                if key.startswith(prefix):
                    uid_str = key.split(":")[-1]
                    if exclude and uid_str == str(exclude):
                        continue
                    try:
                        await queue.put(payload)
                        delivered_uids.add(int(uid_str))
                    except Exception:
                        pass

        # Pending for offline users (system messages that need delivery)
        if member_ids and msg_type in ("message", "thread_message"):
            for uid in member_ids:
                if uid not in delivered_uids and uid != exclude:
                    await pending_queue.enqueue(room_id, uid, payload)

    async def enqueue_pending(self, room_id: int, payload: dict, member_ids: list[int] | None = None):
        """Enqueue message for offline delivery without WS broadcast (BMP-only mode)."""
        if not member_ids or payload.get("type") not in ("message", "thread_message"):
            return
        online = set(self._rooms.get(room_id, {}).keys())
        for uid in member_ids:
            if uid not in online:
                await pending_queue.enqueue(room_id, uid, payload)

    async def send_to_user(self, room_id: int, user_id: int, payload: dict) -> bool:
        conn = self._rooms.get(room_id, {}).get(user_id)
        if not conn:
            return False
        try:
            await conn.websocket.send_text(self._pad_ws_frame(payload))
            return True
        except Exception:
            await self.disconnect(room_id, user_id)
            return False

    @staticmethod
    def _pad_ws_frame(payload: dict) -> str:
        """Добавляет рандомный padding к WS-фрейму (anti DPI size analysis)."""
        import json, secrets
        pad_len = 32 + secrets.randbelow(225)  # 32..256
        payload["_p"] = secrets.token_urlsafe(pad_len)
        return json.dumps(payload)

    async def set_typing(self, room_id: int, user_id: int, is_typing: bool) -> None:
        # BMP mode: typing goes client-to-client via BMP, server does nothing
        # Zero metadata leakage — server never knows who is typing
        pass

    def check_rate_limit(self, room_id: int, user_id: int) -> bool:
        """
        Проверяет Token Bucket для пользователя.
        Возвращает True если сообщение разрешено, False — если превышен лимит.
        """
        conn = self._rooms.get(room_id, {}).get(user_id)
        if not conn:
            return False
        return conn.rate_limiter.consume()

    async def is_duplicate_message(self, msg_id: str) -> bool:
        """
        Проверяет дедупликацию через глобальный кэш.
        Возвращает True если сообщение уже обрабатывалось.
        """
        if not msg_id:
            return False
        return await deduplicator.is_duplicate(msg_id)

    # ── Глобальный WebSocket для уведомлений ────────────────────────────────

    async def connect_global(self, user_id: int, ws: WebSocket) -> None:
        """Подключает глобальный WS для уведомлений пользователя."""
        await ws.accept()
        self._global_ws[user_id] = ws
        logger.debug("Global WS+ (sanitized)")

        # Flush in-memory pending notifications
        flushed = await pending_notifications.flush(user_id, ws)

        # Flush DB-persistent pending notifications
        db_flushed = await self._flush_db_notifications(user_id, ws)

        total = flushed + db_flushed
        if total > 0:
            logger.debug(f"Flushed {total} pending notifications (sanitized)")

    def disconnect_global(self, user_id: int) -> None:
        """Отключает глобальный WS пользователя."""
        self._global_ws.pop(user_id, None)
        logger.debug("Global WS- (sanitized)")

    async def notify_user(self, user_id: int, payload: dict) -> bool:
        """Отправляет уведомление через глобальный WS. Если WS нет — сохраняет в БД."""
        ws = self._global_ws.get(user_id)
        if not ws:
            await self._persist_notification(user_id, payload)
            return False
        try:
            await ws.send_json(payload)
            return True
        except Exception:
            self._global_ws.pop(user_id, None)
            await self._persist_notification(user_id, payload)
            return False

    @staticmethod
    async def _persist_notification(user_id: int, payload: dict) -> None:
        """Сохраняет уведомление в БД для гарантированной доставки."""
        # BMP mode: don't persist content notifications (they go through BMP)
        from app.config import Config
        if Config.BMP_DELIVERY_ENABLED:
            _type = payload.get("type", "")
            # Only persist system notifications (kicked, room_deleted)
            if _type not in ("kicked", "room_deleted", "room_updated"):
                return
        try:
            from app.database import SessionLocal
            from app.models_rooms.encryption import PendingNotification
            db = SessionLocal()
            try:
                notif = PendingNotification(
                    user_id=user_id,
                    payload=_json.dumps(payload, ensure_ascii=False),
                )
                db.add(notif)
                db.commit()
            finally:
                db.close()
        except Exception as e:
            logger.warning("Failed to persist notification (sanitized): %s", type(e).__name__)
            # Fallback — in-memory queue
            await pending_notifications.enqueue(user_id, payload)

    @staticmethod
    async def _flush_db_notifications(user_id: int, ws: WebSocket) -> int:
        """Отправляет все DB-pending уведомления пользователю и удаляет их."""
        try:
            from app.database import SessionLocal
            from app.models_rooms.encryption import PendingNotification
            db = SessionLocal()
            try:
                rows = (
                    db.query(PendingNotification)
                    .filter(PendingNotification.user_id == user_id)
                    .order_by(PendingNotification.created_at.asc())
                    .all()
                )
                if not rows:
                    return 0
                sent = 0
                ids_to_delete = []
                for row in rows:
                    try:
                        data = _json.loads(row.payload)
                        data["_pending"] = True
                        await ws.send_json(data)
                        ids_to_delete.append(row.id)
                        sent += 1
                    except Exception:
                        break
                if ids_to_delete:
                    db.query(PendingNotification).filter(
                        PendingNotification.id.in_(ids_to_delete)
                    ).delete(synchronize_session=False)
                    db.commit()
                return sent
            finally:
                db.close()
        except Exception as e:
            logger.warning("Failed to flush DB notifications for user %s: %s", user_id, e)
            return 0

    def get_online_users(self, room_id: int) -> list[dict]:
        return [
            {
                "user_id":      c.user_id,
                "username":     c.username,
                "display_name": c.display_name,
                "avatar_emoji": c.avatar_emoji,
                "is_typing":    c.is_typing,
            }
            for c in self._rooms.get(room_id, {}).values()
        ]

    def is_online(self, room_id: int, user_id: int) -> bool:
        return user_id in self._rooms.get(room_id, {})

    def is_online_any_room(self, user_id: int) -> bool:
        """Check if user is connected in any room or has a global WS."""
        if user_id in self._global_ws:
            return True
        return any(user_id in users for users in self._rooms.values())

    def count_online_from_set(self, user_ids: set[int]) -> int:
        """Count how many users from the given set are currently online anywhere."""
        online = set(self._global_ws.keys())
        for users in self._rooms.values():
            online.update(users.keys())
        return len(user_ids & online)

    def total_connections(self) -> int:
        return sum(len(v) for v in self._rooms.values())

    async def cleanup_stale(self) -> int:
        """Remove stale WebSocket connections (disconnected but not cleaned up)."""
        from starlette.websockets import WebSocketState
        removed = 0
        async with self._lock:
            # Clean stale room connections
            for room_id in list(self._rooms.keys()):
                for uid in list(self._rooms[room_id].keys()):
                    conn = self._rooms[room_id][uid]
                    ws = conn.websocket
                    if hasattr(ws, 'client_state') and ws.client_state != WebSocketState.CONNECTED:
                        del self._rooms[room_id][uid]
                        removed += 1
                if not self._rooms[room_id]:
                    del self._rooms[room_id]
            # Clean stale global WS
            for uid in list(self._global_ws.keys()):
                ws = self._global_ws[uid]
                if hasattr(ws, 'client_state') and ws.client_state != WebSocketState.CONNECTED:
                    del self._global_ws[uid]
                    removed += 1
        if removed:
            logger.info("Cleaned up %d stale WebSocket connections", removed)
        return removed

    async def close_all(self) -> None:
        """Gracefully close all active WebSocket connections."""
        async with self._lock:
            for room_id, users in list(self._rooms.items()):
                for user_id, entry in list(users.items()):
                    try:
                        await entry.ws.close(code=1001, reason="Server shutting down")
                    except Exception:
                        pass
            self._rooms.clear()
        logger.info("All WebSocket connections closed")

    def dedup_stats(self) -> dict:
        """Возвращает статистику дедупликатора и pending queue для мониторинга."""
        return {
            "seen_msg_ids":  deduplicator.seen_count(),
            "rooms":         len(self._rooms),
            "connections":   self.total_connections(),
            "pending_queue": pending_queue.stats(),
        }


# Глобальный экземпляр менеджера
manager = ConnectionManager()
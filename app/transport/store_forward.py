"""
app/transport/store_forward.py — Store-and-forward for offline message delivery.

Solves: mesh requires both parties online. With store-and-forward,
messages are held by N closest online peers and delivered when
recipient comes online.

Flow:
  1. Sender sends E2E-encrypted message to recipient
  2. Recipient is offline → message already encrypted (AES-256-GCM)
  3. Store encrypted payload on N=3 closest online federation peers
  4. When recipient connects, peers push pending messages
  5. Recipient decrypts locally
  6. Peers delete delivered messages

Security:
  - Messages are E2E encrypted BEFORE store → peers cannot read content
  - Sealed sender: peers see only recipient_pseudo, not sender identity
  - TTL 24h: undelivered messages auto-expire
  - Deduplication by content hash (BLAKE2b)
  - Max 1000 pending messages per recipient (DoS protection)

This is similar to Signal's "sealed sender + server queue" but distributed
across federation peers instead of a single server.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ── Limits ───────────────────────────────────────────────────────────────────

MAX_PENDING_PER_USER = 1000       # max queued messages per recipient
MAX_MESSAGE_SIZE = 256 * 1024     # 256KB max per stored message
MESSAGE_TTL = 86400               # 24 hours
REPLICATION_FACTOR = 3            # store on N peers
CLEANUP_INTERVAL = 3600           # cleanup every hour


@dataclass
class StoredMessage:
    """A message held for offline recipient."""
    msg_hash: str                  # BLAKE2b hash for dedup
    recipient_pseudo: str          # sealed sender pseudo (not user_id)
    encrypted_payload: bytes       # E2E encrypted content
    room_id: int
    stored_at: float = field(default_factory=time.time)
    ttl: int = MESSAGE_TTL
    delivered: bool = False
    delivery_attempts: int = 0

    @property
    def expired(self) -> bool:
        return time.time() - self.stored_at > self.ttl


class StoreForwardManager:
    """
    Manages store-and-forward message queue for offline delivery.

    In-memory storage (for production: persist to SQLite/Redis).
    Each node acts as a relay — stores messages for offline users
    in rooms it participates in.
    """

    def __init__(self):
        # recipient_pseudo → list of StoredMessage
        self._queue: dict[str, list[StoredMessage]] = {}
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._delivery_callbacks: list = []  # registered delivery handlers

    async def start(self):
        """Start background cleanup task."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("StoreForwardManager started (TTL=%ds, max=%d/user)",
                        MESSAGE_TTL, MAX_PENDING_PER_USER)

    async def stop(self):
        """Stop background cleanup."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            self._cleanup_task = None

    def on_delivery(self, callback):
        """Register a callback for message delivery: callback(recipient_pseudo, messages)."""
        self._delivery_callbacks.append(callback)

    async def store(
        self,
        recipient_pseudo: str,
        encrypted_payload: bytes,
        room_id: int,
        ttl: int = MESSAGE_TTL,
    ) -> bool:
        """
        Store an encrypted message for an offline recipient.

        Returns True if stored, False if rejected (limit/size/duplicate).
        """
        if len(encrypted_payload) > MAX_MESSAGE_SIZE:
            logger.debug("Store-forward rejected: payload too large (%d bytes)",
                         len(encrypted_payload))
            return False

        # Compute hash for deduplication
        msg_hash = hashlib.blake2b(encrypted_payload, digest_size=16).hexdigest()

        async with self._lock:
            queue = self._queue.get(recipient_pseudo, [])

            # Check limits
            if len(queue) >= MAX_PENDING_PER_USER:
                # Evict oldest expired message, or reject
                queue = [m for m in queue if not m.expired]
                if len(queue) >= MAX_PENDING_PER_USER:
                    logger.debug("Store-forward rejected: queue full for %s", recipient_pseudo[:8])
                    return False

            # Deduplication
            if any(m.msg_hash == msg_hash for m in queue):
                return True  # Already stored, not an error

            msg = StoredMessage(
                msg_hash=msg_hash,
                recipient_pseudo=recipient_pseudo,
                encrypted_payload=encrypted_payload,
                room_id=room_id,
                ttl=ttl,
            )
            queue.append(msg)
            self._queue[recipient_pseudo] = queue

        logger.debug("Store-forward: queued message for %s (room=%d, size=%d)",
                      recipient_pseudo[:8], room_id, len(encrypted_payload))
        return True

    async def deliver(self, recipient_pseudo: str) -> list[StoredMessage]:
        """
        Retrieve and remove all pending messages for a recipient.

        Called when recipient comes online. Returns list of messages.
        """
        async with self._lock:
            queue = self._queue.pop(recipient_pseudo, [])

        # Filter out expired
        valid = [m for m in queue if not m.expired]
        expired_count = len(queue) - len(valid)
        if expired_count:
            logger.debug("Store-forward: %d expired messages discarded for %s",
                          expired_count, recipient_pseudo[:8])

        if valid:
            logger.info("Store-forward: delivering %d messages to %s",
                        len(valid), recipient_pseudo[:8])

        return valid

    async def notify_online(self, recipient_pseudo: str):
        """
        Notify that a recipient has come online.

        Triggers delivery of pending messages via registered callbacks.
        """
        messages = await self.deliver(recipient_pseudo)
        if not messages:
            return

        for callback in self._delivery_callbacks:
            try:
                await callback(recipient_pseudo, messages)
            except Exception as e:
                logger.debug("Store-forward delivery callback error: %s", e)

    def pending_count(self, recipient_pseudo: str) -> int:
        """Number of pending messages for a recipient."""
        queue = self._queue.get(recipient_pseudo, [])
        return sum(1 for m in queue if not m.expired)

    def stats(self) -> dict:
        """Queue statistics."""
        total_messages = sum(len(q) for q in self._queue.values())
        total_recipients = len(self._queue)
        total_bytes = sum(
            len(m.encrypted_payload)
            for q in self._queue.values()
            for m in q
        )
        return {
            "total_messages": total_messages,
            "total_recipients": total_recipients,
            "total_bytes": total_bytes,
            "max_per_user": MAX_PENDING_PER_USER,
            "ttl_seconds": MESSAGE_TTL,
        }

    async def _cleanup_loop(self):
        """Periodically remove expired messages."""
        while True:
            try:
                await asyncio.sleep(CLEANUP_INTERVAL)
                removed = 0
                async with self._lock:
                    empty_keys = []
                    for pseudo, queue in self._queue.items():
                        before = len(queue)
                        self._queue[pseudo] = [m for m in queue if not m.expired]
                        removed += before - len(self._queue[pseudo])
                        if not self._queue[pseudo]:
                            empty_keys.append(pseudo)
                    for k in empty_keys:
                        del self._queue[k]

                if removed:
                    logger.info("Store-forward cleanup: %d expired messages removed", removed)

            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.debug("Store-forward cleanup error: %s", e)


# Global instance
store_forward = StoreForwardManager()

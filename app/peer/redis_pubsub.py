"""
Redis pub/sub layer for horizontal scaling of WebSocket connections.

When REDIS_URL is set, broadcasts are forwarded through Redis channels so
that all Vortex instances receive messages for rooms they have connected users in.

Architecture:
  Instance A (user in room 1) ──publish──> Redis channel "vortex:room:1"
  Instance B (user in room 1) <──subscribe── Redis channel "vortex:room:1"
  Instance B delivers to its local WebSocket connections.

Without Redis (REDIS_URL empty), everything works as before — single-instance.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_redis_client = None
_pubsub_task: Optional[asyncio.Task] = None
_subscribed_channels: set[str] = set()
_instance_id: str = ""


def _get_prefix() -> str:
    from app.config import Config
    return Config.REDIS_CHANNEL_PREFIX or "vortex"


async def init_redis() -> bool:
    """Initialize Redis connection. Returns True if Redis is available."""
    global _redis_client, _instance_id
    from app.config import Config

    if not Config.REDIS_URL:
        logger.info("Redis not configured — single-instance mode")
        return False

    try:
        import redis.asyncio as aioredis
        _redis_client = aioredis.from_url(
            Config.REDIS_URL,
            max_connections=Config.REDIS_POOL_SIZE,
            decode_responses=True,
            socket_connect_timeout=5,
            retry_on_timeout=True,
        )
        await _redis_client.ping()
        _instance_id = os.getpid().__str__() + "-" + os.urandom(4).hex()
        logger.info("Redis connected (%s), instance_id=%s", Config.REDIS_URL.split("@")[-1], _instance_id)
        return True
    except ImportError:
        logger.warning("redis package not installed — single-instance mode")
        return False
    except Exception as e:
        logger.warning("Redis connection failed: %s — single-instance mode", e)
        _redis_client = None
        return False


async def close_redis() -> None:
    """Gracefully close Redis connection."""
    global _redis_client, _pubsub_task
    if _pubsub_task and not _pubsub_task.done():
        _pubsub_task.cancel()
        try:
            await _pubsub_task
        except (asyncio.CancelledError, Exception):
            pass
    if _redis_client:
        await _redis_client.aclose()
        _redis_client = None
    logger.info("Redis connection closed")


def is_redis_available() -> bool:
    """Check if Redis pub/sub is active."""
    return _redis_client is not None


async def publish_to_room(room_id: int, payload: dict, sender_instance: str = "") -> None:
    """Publish a message to a room channel via Redis."""
    if not _redis_client:
        return
    channel = f"{_get_prefix()}:room:{room_id}"
    message = json.dumps({
        "instance_id": sender_instance or _instance_id,
        "room_id": room_id,
        "payload": payload,
    })
    try:
        await _redis_client.publish(channel, message)
    except Exception as e:
        logger.warning("Redis publish error (room %d): %s", room_id, e)


async def publish_notification(user_id: int, payload: dict) -> None:
    """Publish a notification to a specific user via Redis."""
    if not _redis_client:
        return
    channel = f"{_get_prefix()}:notify:{user_id}"
    message = json.dumps({
        "instance_id": _instance_id,
        "user_id": user_id,
        "payload": payload,
    })
    try:
        await _redis_client.publish(channel, message)
    except Exception as e:
        logger.warning("Redis publish error (user %d): %s", user_id, e)


async def subscribe_room(room_id: int) -> None:
    """Subscribe this instance to a room channel."""
    channel = f"{_get_prefix()}:room:{room_id}"
    if channel in _subscribed_channels:
        return
    _subscribed_channels.add(channel)


async def unsubscribe_room(room_id: int) -> None:
    """Unsubscribe from a room channel if no local users remain."""
    channel = f"{_get_prefix()}:room:{room_id}"
    _subscribed_channels.discard(channel)


async def start_subscriber(on_room_message, on_notification) -> None:
    """Start background task that listens for Redis messages and delivers locally.

    Args:
        on_room_message: async callback(room_id: int, payload: dict)
        on_notification: async callback(user_id: int, payload: dict)
    """
    global _pubsub_task
    if not _redis_client:
        return

    async def _listener():
        import redis.asyncio as aioredis
        pubsub = _redis_client.pubsub()
        pattern = f"{_get_prefix()}:*"
        await pubsub.psubscribe(pattern)
        logger.info("Redis subscriber started (pattern=%s)", pattern)

        try:
            async for msg in pubsub.listen():
                if msg["type"] not in ("pmessage",):
                    continue
                try:
                    data = json.loads(msg["data"])
                    # Skip messages from this instance
                    if data.get("instance_id") == _instance_id:
                        continue

                    channel = msg.get("channel", "")
                    if isinstance(channel, bytes):
                        channel = channel.decode()

                    prefix = _get_prefix()
                    if f"{prefix}:room:" in channel:
                        room_id = int(channel.split(":")[-1])
                        await on_room_message(room_id, data["payload"])
                    elif f"{prefix}:notify:" in channel:
                        user_id = int(channel.split(":")[-1])
                        await on_notification(user_id, data["payload"])
                except Exception as e:
                    logger.warning("Redis message processing error: %s", e)
        except asyncio.CancelledError:
            await pubsub.punsubscribe(pattern)
            await pubsub.aclose()
            raise
        except Exception as e:
            logger.error("Redis subscriber died: %s", e)

    _pubsub_task = asyncio.create_task(_listener(), name="redis-subscriber")


# ── Distributed rate limiter (Redis-based) ────────────────────────────────

async def check_rate_limit_distributed(key: str, limit: int, window: int) -> bool:
    """Check rate limit using Redis sliding window. Returns True if allowed."""
    if not _redis_client:
        return True  # No Redis = no distributed limiting
    try:
        import time
        now = time.time()
        pipe = _redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zadd(key, {f"{now}": now})
        pipe.zcard(key)
        pipe.expire(key, window + 1)
        results = await pipe.execute()
        count = results[2]
        return count <= limit
    except Exception as e:
        logger.warning("Redis rate limit check failed (key=%s): %s", key, e)
        return True  # Fail open


# ── Distributed cache helpers ─────────────────────────────────────────────

async def cache_set(key: str, value: str, ttl: int = 300) -> None:
    """Set a cache value in Redis."""
    if not _redis_client:
        return
    try:
        await _redis_client.setex(f"{_get_prefix()}:cache:{key}", ttl, value)
    except Exception as e:
        logger.warning("Redis cache_set failed (key=%s): %s", key, e)


async def cache_get(key: str) -> Optional[str]:
    """Get a cache value from Redis."""
    if not _redis_client:
        return None
    try:
        return await _redis_client.get(f"{_get_prefix()}:cache:{key}")
    except Exception as e:
        logger.warning("Redis cache_get failed (key=%s): %s", key, e)
        return None


def get_instance_id() -> str:
    """Return this instance's unique ID."""
    return _instance_id

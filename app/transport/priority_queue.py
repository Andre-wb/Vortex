"""
app/transport/priority_queue.py — Priority lanes for message delivery.

Solves: all messages share same delivery pipeline, causing latency spikes
when bulk transfers (files, history sync) compete with real-time signals.

Three priority lanes:
  Lane 0 (REALTIME):  typing, presence, call signaling   → immediate, no batching
  Lane 1 (NORMAL):    text messages, reactions, edits     → 10ms micro-batch
  Lane 2 (BULK):      files, history sync, key backup     → 25ms batch + compression

Each lane has independent send queue and processing loop.
Adaptive compression: zlib for BULK payloads > 1KB.

Architecture:
  ┌──────────┐
  │ Lane 0   │ ← typing, calls → immediate dispatch
  │ (0ms)    │
  ├──────────┤
  │ Lane 1   │ ← messages → 10ms batch window
  │ (10ms)   │
  ├──────────┤
  │ Lane 2   │ ← files, sync → 25ms batch + zlib
  │ (25ms)   │
  └──────────┘
"""
from __future__ import annotations

import asyncio
import logging
import time
import zlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, Optional, Awaitable

logger = logging.getLogger(__name__)


class Priority(IntEnum):
    """Message priority levels."""
    REALTIME = 0   # typing, presence, call signals
    NORMAL = 1     # text messages, reactions
    BULK = 2       # files, history, key sync


# Map message types to priority lanes
_TYPE_PRIORITY: dict[str, Priority] = {
    # Realtime (Lane 0)
    "typing": Priority.REALTIME,
    "typing_stop": Priority.REALTIME,
    "presence": Priority.REALTIME,
    "call_signal": Priority.REALTIME,
    "call_offer": Priority.REALTIME,
    "call_answer": Priority.REALTIME,
    "call_ice": Priority.REALTIME,
    "group_offer": Priority.REALTIME,
    "group_answer": Priority.REALTIME,
    "group_ice": Priority.REALTIME,
    "group_join": Priority.REALTIME,
    "group_leave": Priority.REALTIME,
    "ping": Priority.REALTIME,
    "pong": Priority.REALTIME,

    # Normal (Lane 1)
    "message": Priority.NORMAL,
    "reaction": Priority.NORMAL,
    "edit": Priority.NORMAL,
    "delete": Priority.NORMAL,
    "read": Priority.NORMAL,
    "pin": Priority.NORMAL,
    "poll_vote": Priority.NORMAL,

    # Bulk (Lane 2)
    "file": Priority.BULK,
    "file_chunk": Priority.BULK,
    "history_sync": Priority.BULK,
    "key_sync": Priority.BULK,
    "key_backup": Priority.BULK,
    "member_list": Priority.BULK,
    "room_state": Priority.BULK,
}

# Batch windows per lane (ms)
_BATCH_WINDOW: dict[Priority, float] = {
    Priority.REALTIME: 0,      # immediate
    Priority.NORMAL: 0.010,    # 10ms
    Priority.BULK: 0.025,      # 25ms
}

# Compression threshold for BULK lane
COMPRESSION_THRESHOLD = 1024  # 1KB


def classify_message(msg_type: str) -> Priority:
    """Classify a message type into a priority lane."""
    return _TYPE_PRIORITY.get(msg_type, Priority.NORMAL)


@dataclass
class QueuedMessage:
    """A message waiting in a priority lane."""
    payload: bytes
    destination: str        # "ip:port" or "room:id"
    msg_type: str
    priority: Priority
    queued_at: float = field(default_factory=time.monotonic)


class PriorityDispatcher:
    """
    Dispatches messages through priority lanes with per-lane batching.

    Usage:
        dispatcher = PriorityDispatcher(send_fn=my_send_function)
        await dispatcher.start()

        # Enqueue a message — automatically routed to correct lane
        await dispatcher.enqueue(payload, destination, msg_type="message")
        await dispatcher.enqueue(signal, destination, msg_type="typing")
    """

    MAX_BATCH_SIZE = 20  # max messages per batch

    def __init__(self, send_fn: Callable[[str, list[bytes]], Awaitable[bool]]):
        """
        send_fn: async function(destination, payloads) → bool
            Called to actually send a batch of payloads to a destination.
        """
        self._send_fn = send_fn
        self._queues: dict[Priority, asyncio.Queue] = {
            Priority.REALTIME: asyncio.Queue(),
            Priority.NORMAL: asyncio.Queue(),
            Priority.BULK: asyncio.Queue(),
        }
        self._tasks: list[asyncio.Task] = []
        self._stats = {p: {"sent": 0, "batches": 0, "compressed_bytes": 0} for p in Priority}

    async def start(self):
        """Start per-lane processing loops."""
        for priority in Priority:
            task = asyncio.create_task(self._lane_loop(priority))
            self._tasks.append(task)
        logger.info("PriorityDispatcher started (3 lanes)")

    async def stop(self):
        """Stop all lane loops."""
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()

    async def enqueue(self, payload: bytes, destination: str, msg_type: str = "message"):
        """
        Enqueue a message for delivery.

        Automatically classified into the correct priority lane.
        """
        priority = classify_message(msg_type)
        msg = QueuedMessage(
            payload=payload,
            destination=destination,
            msg_type=msg_type,
            priority=priority,
        )
        await self._queues[priority].put(msg)

    def stats(self) -> dict:
        """Per-lane statistics."""
        return {
            "realtime": {
                "queued": self._queues[Priority.REALTIME].qsize(),
                **self._stats[Priority.REALTIME],
            },
            "normal": {
                "queued": self._queues[Priority.NORMAL].qsize(),
                **self._stats[Priority.NORMAL],
            },
            "bulk": {
                "queued": self._queues[Priority.BULK].qsize(),
                **self._stats[Priority.BULK],
            },
        }

    async def _lane_loop(self, priority: Priority):
        """Processing loop for a single priority lane."""
        queue = self._queues[priority]
        batch_window = _BATCH_WINDOW[priority]

        while True:
            try:
                # Wait for first message
                first = await queue.get()
                batch: dict[str, list[QueuedMessage]] = {}
                batch.setdefault(first.destination, []).append(first)

                if batch_window > 0:
                    # Collect more messages within the batch window
                    deadline = time.monotonic() + batch_window
                    while time.monotonic() < deadline and len(batch) < self.MAX_BATCH_SIZE:
                        try:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                break
                            msg = await asyncio.wait_for(queue.get(), timeout=remaining)
                            batch.setdefault(msg.destination, []).append(msg)
                        except asyncio.TimeoutError:
                            break

                # Send each destination's batch
                for dest, messages in batch.items():
                    payloads = [m.payload for m in messages]

                    # Adaptive compression for BULK lane
                    if priority == Priority.BULK:
                        payloads = self._maybe_compress(payloads)

                    try:
                        await self._send_fn(dest, payloads)
                        self._stats[priority]["sent"] += len(messages)
                        self._stats[priority]["batches"] += 1
                    except Exception as e:
                        logger.debug("Lane %s send error to %s: %s",
                                     priority.name, dest[:30], str(e)[:100])

            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.debug("Lane %s loop error: %s", priority.name, e)

    def _maybe_compress(self, payloads: list[bytes]) -> list[bytes]:
        """Compress payloads in BULK lane if they exceed threshold."""
        result = []
        for p in payloads:
            if len(p) > COMPRESSION_THRESHOLD:
                compressed = zlib.compress(p, level=6)
                if len(compressed) < len(p) * 0.9:  # only if >10% savings
                    self._stats[Priority.BULK]["compressed_bytes"] += len(p) - len(compressed)
                    # Prefix with 0x01 marker for "compressed"
                    result.append(b"\x01" + compressed)
                    continue
            # Prefix with 0x00 marker for "uncompressed"
            result.append(b"\x00" + p)
        return result


def decompress_payload(data: bytes) -> bytes:
    """Decompress a payload received from priority dispatcher."""
    if not data:
        return data
    if data[0:1] == b"\x01":
        return zlib.decompress(data[1:])
    elif data[0:1] == b"\x00":
        return data[1:]
    return data  # No marker — legacy uncompressed

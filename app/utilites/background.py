"""Фоновые задачи со strong-ссылкой.

asyncio держит на задачу только слабую ссылку, поэтому fire-and-forget
create_task() может быть собран сборщиком мусора до завершения. spawn()
удерживает задачу в множестве до её завершения.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any, Optional

_tasks: set[asyncio.Task] = set()


def spawn(coro: Coroutine[Any, Any, Any], *, name: Optional[str] = None) -> asyncio.Task:
    task = asyncio.ensure_future(coro)
    if name:
        task.set_name(name)
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return task

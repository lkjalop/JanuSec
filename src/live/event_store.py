"""In-memory ring buffer event store for FAST_LIVE_MODE.

Designed to keep recent events for:
 - Simple heuristic rules (future batch)
 - Correlation windows
 - Sanitized egress preview

Not thread safe for multi-process; single FastAPI process usage is assumed.
"""
from __future__ import annotations

import os
import threading
from collections import deque
from collections.abc import Iterable
from typing import Any, Deque, Dict, List

_BUFFER_MAX = int(os.getenv('EVENT_BUFFER_MAX', '10000'))
_buffer: deque[dict[str, Any]] = deque(maxlen=_BUFFER_MAX)
_lock = threading.Lock()


def add_events(events: Iterable[dict[str, Any]]) -> int:
    count = 0
    with _lock:
        for ev in events:
            _buffer.append(ev)
            count += 1
    return count


def snapshot(limit: int = 1000) -> list[dict[str, Any]]:
    if limit <= 0:
        limit = 1
    with _lock:
        return list(_buffer)[-limit:]


def size() -> int:
    with _lock:
        return len(_buffer)


def capacity() -> int:
    return _BUFFER_MAX

from __future__ import annotations

import threading
from typing import Any, Dict, List

_LOCK = threading.Lock()
_QUEUE: List[Dict[str, Any]] = []


def enqueue(event_id: str, signals: List[Dict[str, Any]]):
    with _LOCK:
        _QUEUE.append({'event_id': event_id, 'signals': signals})


def drain() -> List[Dict[str, Any]]:
    """Remove and return all queued items."""
    with _LOCK:
        items = list(_QUEUE)
        _QUEUE.clear()
    return items


def peek() -> List[Dict[str, Any]]:
    with _LOCK:
        return list(_QUEUE)

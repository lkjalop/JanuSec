"""Shared in-memory stores for tests and lightweight runtimes.

Modules that need a process-global in-memory fallback should use this
central module so different import aliases (src.repositories.* vs
repositories.*) still reference the same object when sys.path normalization
may differ under tests.
"""
from __future__ import annotations

from typing import Any
from collections import deque
import os

# Default max size for in-memory buffers; can be tuned via env for tests
_DEFAULT_MAX = max(1, int(os.getenv('HUNT_LANE_FALLBACK_MAX', '512')))

# Hunt lane events fallback buffer (deque to cap growth)
HUNT_LANE_EVENTS: deque[dict[str, Any]] = deque(maxlen=_DEFAULT_MAX)


def push_hunt_event(entry: dict[str, Any]) -> None:
    try:
        HUNT_LANE_EVENTS.appendleft(entry)
    except Exception:
        # best-effort
        HUNT_LANE_EVENTS.append(entry)


def get_hunt_events(tenant_id: str | None, lane: str | None, limit: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in HUNT_LANE_EVENTS:
        if tenant_id and item.get('tenant_id') != tenant_id:
            continue
        if lane and item.get('lane') != lane:
            continue
        results.append(dict(item))
        if len(results) >= limit:
            break
    return results


def reset_hunt_events() -> None:
    HUNT_LANE_EVENTS.clear()

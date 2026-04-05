from __future__ import annotations

"""Collector Base Interfaces

Each adapter implements `fetch_events(since_ts: float) -> list[dict]` returning raw
source-native records. Normalization occurs upstream (pipeline module) converting
to unified event schema.

Design goals:
 - Stateless fetch (paged or time-windowed)
 - Graceful degradation when SDK creds absent (return [])
 - Lightweight dependency isolation (import inside method)
"""

from typing import Protocol, List, Dict, Any
import time


class EventCollector(Protocol):
    def fetch_events(self, since_ts: float) -> List[Dict[str, Any]]:  # pragma: no cover - interface
        ...


class NoopCollector:
    """Fallback collector used when integration creds missing."""
    source = "noop"

    def fetch_events(self, since_ts: float) -> List[Dict[str, Any]]:
        return []


def _now() -> float:
    return time.time()


def window_start(minutes: int) -> float:
    return _now() - (minutes * 60.0)


__all__ = ["EventCollector", "NoopCollector", "window_start"]
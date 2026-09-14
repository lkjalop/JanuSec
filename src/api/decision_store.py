"""Decision Store Abstraction.

Provides an optional persistent-ish in‑process store with:
  - Retention by max items
  - Retention by age (seconds)
  - Backward compatibility: legacy DECISION_CACHE (dict) can still point at the store._data

Enable with env DECISION_STORE_ENABLED=1 (default) – if disabled code paths fall back to plain dict logic.
"""
from __future__ import annotations

import os
import time
from collections import deque
import threading
from typing import Any, Deque, Dict, Iterable, Optional


class DecisionStore:
    """A lightweight in-process decision store.

    Public API:
      - add(key, value)
      - get(key)
      - remove(key)
      - keys()
      - values()
      - items()
      - clear()
      - evict_n(n)
      - snapshot()

    The store preserves insertion order and provides O(1) pop-oldest via
    an internal deque. All mutation operations are guarded by a
    threading.Lock to make the store safe for mixed sync/async access in
    our test and server environments.
    """

    def __init__(self, max_items: int = 5000, max_age_seconds: Optional[int] = None) -> None:
        self.max_items = max_items
        self.max_age_seconds = max_age_seconds
        self._data: Dict[str, Any] = {}
        # Maintain insertion order refs for O(1) pops of oldest
        self._order: Deque[tuple[str, float]] = deque()
        # Guard mutations with a thread-safe lock since callers may be
        # synchronous or running inside background threads/tasks.
        self._lock = threading.Lock()

    def _evict_if_needed(self) -> None:
        # Evict by size
        while len(self._data) > self.max_items and self._order:
            k, _ = self._order.popleft()
            self._data.pop(k, None)
        # Evict by age
        if self.max_age_seconds is not None and self.max_age_seconds > 0:
            cutoff = time.time() - self.max_age_seconds
            while self._order and self._order[0][1] < cutoff:
                k, _ = self._order.popleft()
                self._data.pop(k, None)

    def add(self, key: str, value: dict[str, Any]) -> None:
        # Accept either a dict-like payload (has .get) or an object-like
        # decision record (Pydantic model) with attributes like `timestamp`.
        try:
            if hasattr(value, 'get'):
                ts = value.get('ts') or time.time()
            else:
                # Fallback to attribute access for common models
                ts = getattr(value, 'timestamp', None) or getattr(value, 'ts', None) or time.time()
        except Exception:
            ts = time.time()
        with self._lock:
            # Store the value as-is (preserve original object for callers expecting models)
            self._data[key] = value
            self._order.append((key, ts))
            self._evict_if_needed()

    def get(self, key: str) -> Any:
        # Read-only access is okay without lock; keep fast-path.
        return self._data.get(key)

    def values(self) -> Iterable[Any]:  # preserved common usage
        return list(self._data.values())

    def items(self):  # pragma: no cover - convenience
        return list(self._data.items())

    def keys(self):
        return [k for k, _ in list(self._order)]

    def remove(self, key: str) -> Any:
        """Remove a key from the store and return the removed value, or None."""
        with self._lock:
            val = self._data.pop(key, None)
            # remove from order deque efficiently by rebuilding without key
            if self._order:
                try:
                    self._order = deque((kk, ts) for kk, ts in self._order if kk != key)
                except Exception:
                    # fallback: recreate deque from remaining keys
                    self._order = deque((kk, ts) for kk, ts in list(self._order) if kk != key)
            return val

    def clear(self) -> None:
        """Clear all stored entries."""
        with self._lock:
            self._data.clear()
            try:
                self._order.clear()
            except Exception:
                self._order = deque()

    def evict_n(self, n: int) -> int:
        """Evict up to `n` oldest entries and return number evicted."""
        evicted = 0
        with self._lock:
            while evicted < n and self._order:
                k, _ = self._order.popleft()
                if k in self._data:
                    try:
                        self._data.pop(k, None)
                    except Exception:
                        pass
                evicted += 1
        return evicted

    def __len__(self) -> int:
        return len(self._data)

    def snapshot(self) -> dict:
        return {
            'count': len(self._data),
            'max_items': self.max_items,
            'max_age_seconds': self.max_age_seconds,
        }


def build_decision_store_from_env() -> DecisionStore:
    try:
        max_items = int(os.getenv('DECISION_RETENTION_MAX', '5000') or 5000)
    except Exception:
        max_items = 5000
    try:
        max_age = os.getenv('DECISION_RETENTION_SECONDS')
        max_age_s: Optional[int] = int(max_age) if max_age else None
    except Exception:
        max_age_s = None
    return DecisionStore(max_items=max_items, max_age_seconds=max_age_s)


__all__ = ['DecisionStore','build_decision_store_from_env']

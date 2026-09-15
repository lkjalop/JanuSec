from __future__ import annotations
import time, threading
from typing import Dict, Any, Tuple, Optional, Callable

class TimeWindowMap:
    """Map with timestamp pruning (key -> (value, last_seen))."""
    def __init__(self, window_seconds: float):
        self.window = window_seconds
        self._data: Dict[Any, Tuple[Any,float]] = {}
        self._lock = threading.RLock()
    def set(self, key, value):
        with self._lock:
            self._data[key] = (value, time.time())
    def get(self, key):
        with self._lock:
            val = self._data.get(key)
            return val[0] if val else None
    def touch(self, key):
        with self._lock:
            if key in self._data:
                v,_ = self._data[key]
                self._data[key] = (v, time.time())
    def prune(self):
        cutoff = time.time() - self.window
        with self._lock:
            for k,(_,ts) in list(self._data.items()):
                if ts < cutoff:
                    self._data.pop(k, None)
    def size(self) -> int:
        return len(self._data)

class CooldownTracker:
    def __init__(self, cooldown_seconds: float):
        self.cooldown = cooldown_seconds
        self._last: Dict[Any,float] = {}
        self._lock = threading.RLock()
    def allow(self, key) -> bool:
        now = time.time()
        with self._lock:
            last = self._last.get(key)
            if last and (now - last) < self.cooldown:
                return False
            self._last[key] = now
            return True
    def prune(self, window_seconds: Optional[float] = None):
        w = window_seconds or (self.cooldown * 2)
        cutoff = time.time() - w
        with self._lock:
            for k,t in list(self._last.items()):
                if t < cutoff:
                    self._last.pop(k, None)

class BoundedCounterMap:
    def __init__(self, max_items: int):
        self.max_items = max_items
        self._counts: Dict[Any,int] = {}
        self._lock = threading.RLock()
    def inc(self, key, n: int = 1) -> int:
        with self._lock:
            if key not in self._counts and len(self._counts) >= self.max_items:
                return 0
            self._counts[key] = self._counts.get(key,0)+n
            return self._counts[key]
    def get(self, key) -> int:
        return self._counts.get(key,0)
    def items(self):
        return list(self._counts.items())
    def size(self):
        return len(self._counts)

__all__ = ['TimeWindowMap','CooldownTracker','BoundedCounterMap']
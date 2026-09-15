from __future__ import annotations

import time
from threading import Lock
from typing import Any, Dict

_CACHE: Dict[str, tuple[float, Any]] = {}
_LOCK = Lock()
_DEFAULT_TTL = int(__import__('os').getenv('REPUTATION_CACHE_TTL', '300'))

def get(key: str):
    now = time.time()
    with _LOCK:
        rec = _CACHE.get(key)
        if not rec:
            return None
        ts, val = rec
        if now - ts > _DEFAULT_TTL:
            _CACHE.pop(key, None)
            return None
        return val

def setk(key: str, value: Any):
    with _LOCK:
        _CACHE[key] = (time.time(), value)

def clear():
    with _LOCK:
        _CACHE.clear()

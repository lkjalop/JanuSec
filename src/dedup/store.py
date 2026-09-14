from __future__ import annotations

import os
import time
import threading
from typing import Optional

_USE_REDIS = os.getenv('DEDUP_REDIS_URL') is not None
_lock = threading.Lock()

if _USE_REDIS:
    try:
        import redis
        _redis = redis.from_url(os.getenv('DEDUP_REDIS_URL'))
    except Exception:
        _redis = None
else:
    _redis = None

# in-memory fallback
_STORE = {}

def dedup_check_set(key: str, ttl: int = 3600) -> bool:
    """Return True if key was newly set (not seen before)."""
    if _redis:
        try:
            return _redis.set(key, '1', ex=ttl, nx=True)
        except Exception:
            pass
    # fallback
    now = int(time.time())
    with _lock:
        exp = _STORE.get(key)
        if exp and exp > now:
            return False
        _STORE[key] = now + ttl
        # prune small
        if len(_STORE) > 10000:
            for k in list(_STORE.keys())[:1000]:
                if _STORE[k] <= now:
                    del _STORE[k]
        return True

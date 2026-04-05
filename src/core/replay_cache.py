"""Replay cache abstraction.

Tries Redis first (aioredis), falls back to an in-memory LRU-like set with TTL.
"""
from __future__ import annotations

import os
import time
from typing import Optional

try:
    import redis
except Exception:
    redis = None  # type: ignore


class ReplayCache:
    def __init__(self):
        self.redis_url = os.getenv('REPLAY_REDIS_URL')
        self.use_redis = bool(self.redis_url and redis is not None)
        if self.use_redis:
            try:
                self.client = redis.Redis.from_url(self.redis_url)
            except Exception:
                self.client = None
                self.use_redis = False
        self.mem = set()
        self.mem_ts = {}
        self.window = int(os.getenv('REPLAY_WINDOW_S', '300'))

    def add(self, key: str) -> bool:
        """Return True if key was new, False if it already existed."""
        if self.use_redis and self.client:
            try:
                # setnx returns 1 if set
                added = self.client.setnx(f"replay:{key}", '1')
                if added:
                    self.client.expire(f"replay:{key}", self.window)
                return bool(added)
            except Exception:
                pass
        # fallback in-memory
        now = time.time()
        if key in self.mem:
            return False
        self.mem.add(key)
        self.mem_ts[key] = now
        # prune
        cutoff = now - self.window
        to_remove = [k for k, t in self.mem_ts.items() if t < cutoff]
        for k in to_remove:
            self.mem.discard(k); self.mem_ts.pop(k, None)
        return True

    def exists(self, key: str) -> bool:
        if self.use_redis and self.client:
            try:
                return self.client.exists(f"replay:{key}") == 1
            except Exception:
                pass
        return key in self.mem


_GLOBAL_REPLAY = ReplayCache()

def replay_add(key: str) -> bool:
    return _GLOBAL_REPLAY.add(key)

def replay_exists(key: str) -> bool:
    return _GLOBAL_REPLAY.exists(key)

__all__ = ['replay_add', 'replay_exists', 'ReplayCache']

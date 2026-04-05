"""Simple geo enrichment cache with optional Redis backend.

Usage: instantiate GeoCache() which will connect to Redis if REDIS_URL env var
is set and `redis` package is available; otherwise falls back to an in-memory dict.
"""
from __future__ import annotations
import os
import time
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


class InMemoryCache:
    def __init__(self):
        self.store = {}

    def get(self, key: str) -> Optional[Any]:
        v = self.store.get(key)
        return v

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        # ignore ttl for in-memory cache
        self.store[key] = value


class GeoCache:
    def __init__(self):
        self._client = None
        self._use_redis = False
        self._mem = InMemoryCache()
        try:
            url = os.getenv('REDIS_URL')
            if url:
                try:
                    import redis
                    self._client = redis.StrictRedis.from_url(url, decode_responses=True)
                    # quick smoke test
                    self._client.ping()
                    self._use_redis = True
                except Exception:
                    logger.warning('Redis not available, falling back to in-memory cache')
                    self._client = None
                    self._use_redis = False
        except Exception:
            logger.exception('failed to init GeoCache')

    def _redis_key(self, ip: str) -> str:
        return f'geo:{ip}'

    def get(self, ip: str):
        try:
            if self._use_redis and self._client is not None:
                v = self._client.get(self._redis_key(ip))
                if v:
                    import json
                    return json.loads(v)
                return None
            return self._mem.get(ip)
        except Exception:
            logger.exception('cache get failed')
            return None

    def set(self, ip: str, value, ttl: int = 3600):
        try:
            if self._use_redis and self._client is not None:
                import json
                self._client.set(self._redis_key(ip), json.dumps(value), ex=ttl)
                return
            self._mem.set(ip, value)
        except Exception:
            logger.exception('cache set failed')


_GLOBAL_CACHE = None


def get_global_cache():
    global _GLOBAL_CACHE
    if _GLOBAL_CACHE is None:
        _GLOBAL_CACHE = GeoCache()
    return _GLOBAL_CACHE


__all__ = ['GeoCache', 'get_global_cache']

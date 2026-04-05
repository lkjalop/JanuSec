"""Unified alert/event deduplication service.

Provides in-memory TTL-based suppression with optional Redis backend
for multi-process high availability (future extension). For now, Redis
support is a stub that can be evolved by checking REDIS_URL.

API:
  service = DedupService(ttl_seconds=30)
  first = service.reserve(key)  # True if first occurrence within TTL window
  seen = service.seen(key)

Metrics (pseudo; integrate with metrics library if available):
  - dedup_reservations_total
  - dedup_suppressed_total
"""
from __future__ import annotations

import os
import time
import threading
from typing import Dict


class DedupService:
    def __init__(self, ttl_seconds: float = 30.0, cleanup_interval: float = 60.0, redis_url: str | None = None, key_prefix: str | None = None):
        self.ttl_seconds = float(ttl_seconds)
        self._store: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._reservations = 0
        self._suppressed = 0
        self._cleanup_interval = cleanup_interval
        self._started = False
        # Optional Redis backend for cross-process dedup
        self._redis = None
        self._key_prefix = (key_prefix or os.getenv('DEDUP_KEY_PREFIX') or 'dedup:')
        try:
            url = redis_url or os.getenv('DEDUP_REDIS_URL')
            if url:
                import redis  # type: ignore
                # Keep timeouts small to avoid blocking request paths
                self._redis = redis.from_url(url, socket_timeout=0.5, socket_connect_timeout=0.5)
                # Ping best-effort; if fails, fallback to memory
                try:
                    self._redis.ping()
                except Exception:
                    self._redis = None
        except Exception:
            self._redis = None
        self._maybe_start_cleanup()

    def _maybe_start_cleanup(self):
        # Avoid starting background cleanup thread during unit tests
        import sys
        if os.getenv('FAST_TEST_MODE', '').lower() in {'1', 'true', 'yes'} or os.getenv('PYTEST_CURRENT_TEST') or ('pytest' in sys.modules):
            return
        if self._started or self._cleanup_interval <= 0:
            return
        self._started = True
        def _loop():
                while True:
                    try:
                        # In test mode prefer a very short interval to keep tests fast
                        if os.getenv('FAST_TEST_MODE', '').lower() in {'1', 'true', 'yes'} or os.getenv('PYTEST_CURRENT_TEST'):
                            sleep_for = float(os.getenv('TEST_LOOP_INTERVAL') or 0.1)
                        else:
                            try:
                                tsi = int(os.getenv('TEST_LOOP_INTERVAL') or 0)
                            except Exception:
                                tsi = 0
                            sleep_for = tsi if tsi > 0 else self._cleanup_interval
                        time.sleep(max(0.01, float(sleep_for)))
                    except Exception:
                        try:
                            time.sleep(max(0.01, float(self._cleanup_interval)))
                        except Exception:
                            time.sleep(0.01)
        if not (os.getenv('FAST_TEST_MODE', '').lower() in {'1', 'true', 'yes'} or os.getenv('PYTEST_CURRENT_TEST')):
            th = threading.Thread(target=_loop, name='dedup-cleanup', daemon=True)
            th.start()

    def _cleanup(self):
        now = time.time()
        with self._lock:
            # Use the instance TTL for deterministic behavior in tests; the env var
            # is only applied on global singleton instantiation. Dynamic env-based
            # overrides during runtime caused flakiness when tests created short-TTL
            # instances while a global, longer env TTL was present.
            ttl = self.ttl_seconds
            for k, ts in list(self._store.items()):
                if now - ts >= ttl:
                    self._store.pop(k, None)

    def reserve(self, key: str) -> bool:
        """Reserve key, returning True if first within TTL window, False if suppressed."""
        if not key:
            return True
        ttl = float(self.ttl_seconds)
        # Prefer Redis when configured
        if self._redis is not None:
            try:
                # SET key with NX and EX ttl; returns True if set (first), None/False otherwise
                k = f"{self._key_prefix}{key}"
                ok = self._redis.set(k, '1', ex=int(max(1, ttl)), nx=True)
                if ok:
                    self._reservations += 1
                    return True
                else:
                    self._suppressed += 1
                    return False
            except Exception:
                # On Redis error, fallback to memory for this call
                pass
        now = time.time()
        with self._lock:
            ts = self._store.get(key)
            if ts is not None and (now - ts) < ttl:
                self._suppressed += 1
                return False
            self._store[key] = now
            self._reservations += 1
            return True

    def get_or_set(self, key: str, ttl_seconds: float | None = None) -> bool:
        """Atomic dedup check. Returns True if key is new within TTL window."""
        if not key:
            return True
        ttl = float(ttl_seconds if ttl_seconds is not None else self.ttl_seconds)
        if self._redis is not None:
            try:
                k = f"{self._key_prefix}{key}"
                ok = self._redis.set(k, '1', ex=int(max(1, ttl)), nx=True)
                if ok:
                    self._reservations += 1
                    return True
                self._suppressed += 1
                return False
            except Exception:
                pass
        now = time.time()
        with self._lock:
            ts = self._store.get(key)
            if ts is not None and (now - ts) < ttl:
                self._suppressed += 1
                return False
            self._store[key] = now
            self._reservations += 1
            return True

    def seen(self, key: str) -> bool:
        if not key:
            return False
        ttl = float(self.ttl_seconds)
        if self._redis is not None:
            try:
                k = f"{self._key_prefix}{key}"
                # If key exists and TTL positive, consider seen
                tt = self._redis.ttl(k)
                if tt is None:
                    # redis-py may return None on missing; fall back to EXISTS
                    return bool(self._redis.exists(k))
                return tt > 0
            except Exception:
                # fall back to memory
                pass
        with self._lock:
            ts = self._store.get(key)
            if ts is None:
                return False
            now = time.time()
            age = now - ts
            if age >= ttl:
                # prune immediately for deterministic tests instead of waiting for background cleanup
                self._store.pop(key, None)
                return False
            return True

    def stats(self) -> dict:
        return {
            'ttl_seconds': self.ttl_seconds,
            'reservations': self._reservations,
            'suppressed': self._suppressed,
            'store_size': len(self._store),
        }


# Global instance (configurable via env)

def _create_global_service() -> DedupService:
    try:
        ttl = float(os.getenv('ALERT_DEDUP_TTL_SECONDS', '30') or 30.0)
    except Exception:
        ttl = 30.0
    # Wire Redis when available via env
    redis_url = os.getenv('DEDUP_REDIS_URL')
    prefix = os.getenv('DEDUP_KEY_PREFIX') or 'dedup:'
    return DedupService(ttl_seconds=ttl, redis_url=redis_url, key_prefix=prefix)

# Lazy global accessor to avoid reading env/config at import time in tests.
_GLOBAL_DEDUP_SERVICE: DedupService | None = None

def get_dedup_service(ttl_seconds: float | None = None) -> DedupService:
    """Return the singleton DedupService. If `ttl_seconds` is provided and the
    service is not yet created, it will initialize with that TTL. This allows
    tests to inject a short TTL deterministically before any reservations occur.
    """
    global _GLOBAL_DEDUP_SERVICE
    if _GLOBAL_DEDUP_SERVICE is None:
        if ttl_seconds is not None:
            _GLOBAL_DEDUP_SERVICE = DedupService(ttl_seconds=float(ttl_seconds))
        else:
            _GLOBAL_DEDUP_SERVICE = _create_global_service()
    return _GLOBAL_DEDUP_SERVICE

__all__ = ['DedupService', 'get_dedup_service']


def reset_for_tests() -> None:
    """Reset global dedup service for test isolation (best-effort)."""
    try:
        global _GLOBAL_DEDUP_SERVICE
        g = _GLOBAL_DEDUP_SERVICE
        if g is not None:
            try:
                with g._lock:
                    g._store.clear()
                    g._reservations = 0
                    g._suppressed = 0
            except Exception:
                pass
        # allow tests to re-create a fresh service by setting to None
        _GLOBAL_DEDUP_SERVICE = None
    except Exception:
        pass


__all__.append('reset_for_tests')

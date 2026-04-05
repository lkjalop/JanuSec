"""Redis-backed temporal cache for correlation factor timestamps.

This module provides a RedisTemporalCache that stores per-host factor timestamps
in Redis for cross-process temporal correlation. If Redis is unavailable, a
lightweight in-memory fallback is used.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Dict, List, Optional

from core.metrics.registry import metric_gauge, metric_counter  # type: ignore

logger = logging.getLogger(__name__)

# Counters for temporal cache hits/misses (idempotent registration)
try:
    _CACHE_HIT = metric_counter('correlation', 'temporal_cache_hits', 'Temporal cache hits', labels=['tenant'])
    _CACHE_MISS = metric_counter('correlation', 'temporal_cache_misses', 'Temporal cache misses', labels=['tenant'])
    _CACHE_LEGACY_FALLBACK = metric_counter('correlation', 'temporal_cache_legacy_fallback', 'Temporal cache legacy public namespace fallback used', labels=['tenant'])
except Exception:
    _CACHE_HIT = None
    _CACHE_MISS = None
    _CACHE_LEGACY_FALLBACK = None


def _make_host_key(tenant_id: str | None, host: str) -> str:
    """Construct a host key strictly scoped to the tenant when provided.

    Behavior:
      - tenant_id provided -> janusec:correlation:host:{tenant_id}:{host}
      - tenant_id None -> janusec:correlation:host:{host}
    Do NOT probe any public namespace fallback to avoid cross-tenant leakage.
    """
    if tenant_id:
        return f'janusec:correlation:host:{tenant_id}:{host}'
    return f'janusec:correlation:host:{host}'


class InMemoryTemporalCache:
    def __init__(self):
        from collections import defaultdict, deque
        self.host_factor_times: dict[str, dict[str, float]] = defaultdict(dict)

    def record(self, host: str, factors: list[str], window_seconds: int, tenant_id: str | None = None) -> None:
        now = time.time()
        d = self.host_factor_times[host]
        for f in factors:
            d[f] = now
            # update metric for in-memory impl
            try:
                from core.metrics.registry import metric_gauge  # type: ignore
                g = metric_gauge('correlation','host_count','Per-tenant host set size', labels=['tenant'])
                if g:
                    g.labels(tenant=tenant_id or 'public').set(self.host_count(tenant_id))
            except Exception:
                pass

    def seen_within(self, host: str, factor: str, seconds: int, tenant_id: str | None = None) -> bool:
        d = self.host_factor_times.get(host, {})
        ts = d.get(factor)
        if not ts:
            return False
        return (time.time() - ts) <= seconds

    def host_count(self, tenant_id: str | None = None) -> int:
        # In-memory impl is single-namespace; tenant_id is informational for metrics
        return len(self.host_factor_times)

    def cleanup_hosts(self) -> int:
        # No-op cleanup for in-memory cache; return 0 and update metric
        try:
            from core.metrics.registry import metric_gauge  # type: ignore
            g = metric_gauge('correlation','host_count','Per-tenant host set size', labels=['tenant'])
            if g:
                g.labels(tenant='public').set(self.host_count())
        except Exception:
            pass
        return 0

    def _set_host_count_metric(self, tenant_id: str | None = None) -> None:
        try:
            g = metric_gauge('correlation','host_count','Per-tenant host set size', labels=['tenant'])
            if g:
                g.labels(tenant=tenant_id or 'public').set(self.host_count(tenant_id))
        except Exception:
            pass


class RedisTemporalCache:
    def __init__(self, redis_url: str | None):
        self.redis = None
        self.host_set_key = 'janusec:correlation:hosts'
        if not redis_url:
            raise RuntimeError('redis_url required')
        try:
            import redis
            self.redis = redis.Redis.from_url(redis_url)
        except Exception as exc:
            logger.debug('RedisTemporalCache init failed: %s', exc)
            self.redis = None

    def record(self, host: str, factors: list[str], window_seconds: int, tenant_id: str | None = None) -> None:
        if not self.redis:
            return
        try:
            # Use tenant-scoped host_set when tenant_id provided to avoid multi-tenant leakage
            hs_key = f'{self.host_set_key}:{tenant_id}' if tenant_id else self.host_set_key
            # Build host key strictly scoped to tenant when provided; do NOT fallback to a public namespace
            host_key = _make_host_key(tenant_id, host)
            # Atomic Lua script: HSET factor timestamps, EXPIRE host key, SADD host into host_set
            now = str(time.time())
            lua = """
local host_key = KEYS[1]
local host_set = KEYS[2]
local ttl = tonumber(ARGV[1])
local ts = ARGV[2]
-- ARGV[3..(n-1)] are factor names; last ARGV is the host name
for i=3,#ARGV-1 do
  redis.call('HSET', host_key, ARGV[i], ts)
end
redis.call('EXPIRE', host_key, ttl)
-- Add host into host_set; only set host_set TTL when the host was newly added to avoid refreshing TTL on every record
local added = redis.call('SADD', host_set, ARGV[#ARGV])
if added == 1 then
    redis.call('EXPIRE', host_set, ttl * 4)
end
return 1
"""
            args = [int(window_seconds), now] + list(factors) + [host]
            # KEYS: host_key, hs_key
            try:
                self.redis.eval(lua, 2, host_key, hs_key, *args)
            except Exception:
                # Fallback for environments where EVAL is unsupported (e.g., some fakeredis versions)
                # Perform equivalent operations without atomicity (acceptable for tests)
                for f in factors:
                    try:
                        self.redis.hset(host_key, f, now)
                    except Exception:
                        pass
                try:
                    self.redis.expire(host_key, int(window_seconds))
                except Exception:
                    pass
                try:
                    self.redis.sadd(hs_key, host)
                except Exception:
                    pass
            # update per-tenant host_count metric
            try:
                g = metric_gauge('correlation','host_count','Per-tenant host set size', labels=['tenant'])
                if g:
                    g.labels(tenant=tenant_id or 'public').set(int(self.redis.scard(hs_key) or 0))
            except Exception:
                pass
        except Exception as exc:
            logger.debug('RedisTemporalCache.record failed: %s', exc)

    def seen_within(self, host: str, factor: str, seconds: int, tenant_id: str | None = None) -> bool:
        if not self.redis:
            return False
        try:
            # Use strict tenant-scoped host key construction. Do NOT fall back to any public namespace.
            host_key = _make_host_key(tenant_id, host)
            v = self.redis.hget(host_key, factor)
            if not v:
                # Optional: legacy fallback if env flag enabled (for transitional deployments)
                if os.getenv('CORRELATION_TEMPORAL_PUBLIC_FALLBACK','').lower() in ('1','true','yes') and tenant_id is not None:
                    legacy_key = _make_host_key(None, host)
                    v = self.redis.hget(legacy_key, factor)
                    if v and _CACHE_LEGACY_FALLBACK:
                        try: _CACHE_LEGACY_FALLBACK.labels(tenant=tenant_id or 'public').inc()
                        except Exception: pass
                        try:
                            logger.warning('DEPRECATION: Legacy temporal cache public fallback used for tenant=%s host=%s factor=%s. Disable CORRELATION_TEMPORAL_PUBLIC_FALLBACK to enforce strict isolation.', tenant_id, host, factor)
                        except Exception:
                            pass
                    if not v:
                        return False
                else:
                    return False
            try:
                ts = float(v.decode() if isinstance(v, bytes) else v)
                res = (time.time() - ts) <= seconds
                # Update hit/miss metrics
                try:
                    if res:
                        if _CACHE_HIT:
                            _CACHE_HIT.labels(tenant=tenant_id or 'public').inc()
                    else:
                        if _CACHE_MISS:
                            _CACHE_MISS.labels(tenant=tenant_id or 'public').inc()
                except Exception:
                    pass
                return res
            except Exception:
                # Count as miss on decode/parsing errors
                try:
                    if _CACHE_MISS:
                        _CACHE_MISS.labels(tenant=tenant_id or 'public').inc()
                except Exception:
                    pass
                return False
        except Exception as exc:
            logger.debug('RedisTemporalCache.seen_within failed: %s', exc)
            return False

    def host_count(self) -> int:
        # Deprecated single-arg host_count left for backward compatibility; prefer host_count(tenant_id)
        return self.host_count_for_tenant(None)

    def host_count_for_tenant(self, tenant_id: str | None = None) -> int:
        if not self.redis:
            return 0
        try:
            hs_key = f'{self.host_set_key}:{tenant_id}' if tenant_id else self.host_set_key
            return int(self.redis.scard(hs_key) or 0)
        except Exception:
            return 0

    def cleanup_hosts(self, max_scan: int = 1000, tenant_id: str | None = None) -> int:
        """Attempt to remove hosts from the host set that no longer have an
        associated host key in Redis. Returns number of removed entries. This is
        best-effort and safe to call periodically.
        """
        if not self.redis:
            return 0
        try:
            removed = 0
            cursor = 0
            hs_key = f'{self.host_set_key}:{tenant_id}' if tenant_id else self.host_set_key
            # Use SSCAN to iterate host_set without blocking redis
            while True:
                cursor, items = self.redis.sscan(hs_key, cursor=cursor, count=100)
                for host in items:
                    h = host.decode() if isinstance(host, bytes) else host
                    # Check tenant-scoped host key only (do not check a public namespace)
                    host_key_tenant = _make_host_key(tenant_id, h)
                    if not self.redis.exists(host_key_tenant):
                        # remove from set
                        self.redis.srem(hs_key, h)
                        removed += 1
                        if removed >= max_scan:
                            return removed
                if cursor == 0:
                    break
            return removed
        except Exception:
            return 0
        finally:
            # update host_count metric for tenant
            try:
                hs_key = f'{self.host_set_key}:{tenant_id}' if tenant_id else self.host_set_key
                g = metric_gauge('correlation','host_count','Per-tenant host set size', labels=['tenant'])
                if g:
                    g.labels(tenant=tenant_id or 'public').set(int(self.redis.scard(hs_key) or 0))
            except Exception:
                pass


def build_cache(redis_url: str | None):
    if redis_url:
        try:
            return RedisTemporalCache(redis_url)
        except Exception:
            pass
    return InMemoryTemporalCache()

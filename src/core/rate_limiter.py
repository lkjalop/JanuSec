from __future__ import annotations
import logging
import os
import time
from prometheus_client import Gauge

from .redis_helpers import get_redis_client

logger = logging.getLogger(__name__)

# Metric for monitoring zset sizes
LLM_RATE_ZSET_GAUGE = Gauge('llm_rate_limiter_zset_size', 'Size of LLM rate limiter zset')


def zset_key() -> str:
    return os.getenv('LLM_RATE_ZSET_KEY', 'llm:rate:usage')


def add_usage(member: str, score: float | None = None) -> None:
    client = get_redis_client()
    if client is None:
        return
    try:
        sc = score if score is not None else time.time()
        client.zadd(zset_key(), {member: sc})
    except Exception:
        logger.exception('Failed adding usage to zset')


def cleanup_old_entries(max_age_seconds: int = 3600) -> int:
    """Remove zset entries older than now - max_age_seconds and update metric.

    Returns number of removed entries.
    """
    client = get_redis_client()
    if client is None:
        return 0
    try:
        thresh = time.time() - max_age_seconds
        removed = client.zremrangebyscore(zset_key(), '-inf', thresh)
        try:
            size = client.zcard(zset_key())
            LLM_RATE_ZSET_GAUGE.set(size)
        except Exception:
            pass
        return int(removed or 0)
    except Exception:
        logger.exception('Failed cleaning up rate limiter zset')
        return 0


def start_rate_limiter_cleanup(app) -> None:
    """Start periodic cleanup loop for the rate-limiter zset."""
    import asyncio
    try:
        if os.getenv('FAST_TEST_MODE','').lower() in {'1','true','yes'}:
            return
        interval = int(os.getenv('LLM_RATE_CLEAN_INTERVAL_SECONDS', '300') or 300)

        async def _loop():
            while True:
                try:
                    max_age = int(os.getenv('LLM_RATE_MAX_AGE_SECONDS', '3600') or 3600)
                    removed = cleanup_old_entries(max_age)
                    if removed:
                        logger.info('Rate-limiter cleanup removed %d entries', removed)
                except Exception:
                    logger.exception('Error in rate-limiter cleanup task')
                await asyncio.sleep(max(5, interval))

        loop = asyncio.get_event_loop()
        task = loop.create_task(_loop())
        try:
            app.state._rate_limiter_cleanup_task = task
        except Exception:
            pass
    except Exception:
        logger.exception('Failed starting rate limiter cleanup')
import os
import time
from typing import Optional

_redis_url = os.environ.get('RATE_LIMIT_REDIS_URL')


class RateLimiter:
    def __init__(self, per_min: int = 60):
        self.per_min = per_min
        self._local = {}
        self._use_redis = False
        if _redis_url:
            try:
                import redis
                self._r = redis.from_url(_redis_url)
                self._use_redis = True
            except Exception:
                self._use_redis = False

    def allow(self, actor: str) -> bool:
        if self._use_redis:
            # Use fixed window counter for simplicity
            window = int(time.time()) // 60
            key = f"ratelimit:{actor}:{window}"
            try:
                v = self._r.incr(key)
                if v == 1:
                    self._r.expire(key, 70)
                return v <= self.per_min
            except Exception:
                # fallback to local
                pass
        # local fallback
        window = int(time.time()) // 60
        st = self._local.get(actor, {'window': window, 'count': 0})
        if st['window'] != window:
            st = {'window': window, 'count': 0}
        if st['count'] >= self.per_min:
            self._local[actor] = st
            return False
        st['count'] += 1
        self._local[actor] = st
        return True

"""Redis-backed scheduler with rate-limiting and basic metrics.

This module is optional and guarded by presence of `redis` package and
`ENABLE_REDIS_SCHEDULER` env flag. It stores job registry as Redis hashes
and uses a simple token-bucket rate limiter per upstream host.
"""
from __future__ import annotations

import os
import time
import json
import asyncio
from typing import Optional

try:
    import aioredis
except Exception:  # pragma: no cover - optional
    aioredis = None
try:
    from prometheus_client import Counter, Gauge
except Exception:
    Counter = None
    Gauge = None

from src.enrichment.clients import fetch_epss_for_hash

REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
SCHEDULER_NAMESPACE = "enrich:scheduler"
RATE_BUCKET_PREFIX = "enrich:rate"


class RedisScheduler:
    def __init__(self, redis_url: str = REDIS_URL):
        if aioredis is None:
            raise RuntimeError("aioredis not installed")
        self.redis = None
        self.redis_url = redis_url
        # metrics
        try:
            self.jobs_migrated = Gauge('enrich_scheduler_jobs_migrated', 'Number of jobs migrated to redis') if Gauge else None
            self.rate_drop_counter = Counter('enrich_scheduler_rate_drops_total', 'Rate limiter drops') if Counter else None
            self.run_errors = Counter('enrich_scheduler_run_errors_total', 'Errors in scheduler loop') if Counter else None
        except Exception:
            self.jobs_migrated = None
            self.rate_drop_counter = None
            self.run_errors = None

    async def connect(self):
        self.redis = await aioredis.from_url(self.redis_url)

    async def schedule(self, key: str, payload: dict, interval: int = 3600):
        job_key = f"{SCHEDULER_NAMESPACE}:{key}"
        now = int(time.time())
        job = {"payload": json.dumps(payload), "interval": interval, "next_run": now}
        await self.redis.hset(job_key, mapping=job)
        try:
            if self.jobs_migrated is not None:
                try:
                    # increment gauge by 1 migration marker (gauge used as counter here)
                    self.jobs_migrated.inc()
                except Exception:
                    pass
        except Exception:
            pass

    async def list_jobs(self):
        keys = await self.redis.keys(f"{SCHEDULER_NAMESPACE}:*")
        out = []
        for k in keys:
            data = await self.redis.hgetall(k)
            if data:
                out.append({"key": k.decode().split(":", 2)[-1], "data": {kk.decode(): vv.decode() for kk, vv in data.items()}})
        return out

    async def run_loop(self, stop_event: asyncio.Event):
        # Simple loop: iterate job keys, run due ones subject to rate limiter
        while not stop_event.is_set():
            try:
                keys = await self.redis.keys(f"{SCHEDULER_NAMESPACE}:*")
                now = int(time.time())
                for k in keys:
                    job = await self.redis.hgetall(k)
                    if not job:
                        continue
                    next_run = int(job.get(b"next_run", b"0"))
                    interval = int(job.get(b"interval", b"3600"))
                    payload = json.loads(job.get(b"payload", b"{}"))
                    # Rate limiting: token bucket per upstream host (if provided)
                    upstream = payload.get("upstream")
                    if upstream and not await self._consume_token(upstream):
                        try:
                            if self.rate_drop_counter is not None:
                                self.rate_drop_counter.inc()
                        except Exception:
                            pass
                        continue
                    if now >= next_run:
                        # run fetch
                        try:
                            await fetch_epss_for_hash(payload.get("hash"))
                        except Exception:
                            pass
                        # schedule next with jitter
                        # jitter approx ±10% of interval
                        jitter = int(interval * 0.1)
                        next_ts = now + interval + (int(time.time() * 1000) % (2 * jitter) - jitter)
                        await self.redis.hset(k, mapping={"next_run": next_ts})
            except Exception:
                try:
                    if self.run_errors is not None:
                        self.run_errors.inc()
                except Exception:
                    pass
                await asyncio.sleep(1)
            await asyncio.sleep(1)

    async def _consume_token(self, upstream: str, capacity: int = 5, refill_sec: int = 60) -> bool:
        key = f"{RATE_BUCKET_PREFIX}:{upstream}"
        now = int(time.time())
        data = await self.redis.hgetall(key)
        if not data:
            # initialize
            await self.redis.hset(key, mapping={"tokens": capacity - 1, "last": now})
            return True
        tokens = int(data.get(b"tokens", b"0"))
        last = int(data.get(b"last", b"0"))
        # refill
        delta = now - last
        add = (delta * capacity) // refill_sec
        tokens = min(capacity, tokens + add)
        if tokens <= 0:
            # update last
            await self.redis.hset(key, mapping={"tokens": tokens, "last": now})
            return False
        tokens -= 1
        await self.redis.hset(key, mapping={"tokens": tokens, "last": now})
        return True


_GLOBAL_SCHEDULER: Optional[RedisScheduler] = None


async def get_global_scheduler() -> Optional[RedisScheduler]:
    global _GLOBAL_SCHEDULER
    if _GLOBAL_SCHEDULER is None:
        if aioredis is None:
            return None
        _GLOBAL_SCHEDULER = RedisScheduler()
        await _GLOBAL_SCHEDULER.connect()
    return _GLOBAL_SCHEDULER

"""Simple token-bucket rate limiter used for connector calls.

Provides per-key rate limiting with asynchronous consumption.
"""
from __future__ import annotations

import time
import asyncio
from typing import Dict


class TokenBucketLimiter:
    def __init__(self, rate_per_second: float = 5.0, burst: float = 10.0):
        self._rate = max(0.001, float(rate_per_second))
        self._burst = max(self._rate, float(burst))
        self._store: Dict[str, tuple[float, float, float]] = {}
        self._lock = asyncio.Lock()

    async def consume(self, key: str, *, tokens: float = 1.0) -> None:
        async with self._lock:
            now = time.time()
            last, tokens_avail, rate = self._store.get(key, (now, self._burst, self._rate))
            # refill
            elapsed = max(0.0, now - last)
            tokens_avail = min(self._burst, tokens_avail + elapsed * rate)
            if tokens_avail < tokens:
                # compute wait time
                need = tokens - tokens_avail
                wait = need / rate
                await asyncio.sleep(wait)
                now2 = time.time()
                elapsed2 = max(0.0, now2 - now)
                tokens_avail = min(self._burst, tokens_avail + elapsed2 * rate)
            tokens_avail -= tokens
            self._store[key] = (time.time(), tokens_avail, rate)

import os
import random
import threading
from collections import deque, defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, Optional, Tuple


@dataclass
class TokenBucket:
    capacity: int
    refill_rate_per_sec: float
    tokens: float
    last_refill: float

    def refill(self, now: Optional[float] = None) -> None:
        now = now or time.time()
        elapsed = max(0.0, now - self.last_refill)
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate_per_sec)
            self.last_refill = now

    def try_consume(self, amount: float = 1.0, now: Optional[float] = None) -> bool:
        self.refill(now)
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


class BucketRegistry:
    def __init__(self) -> None:
        self._buckets: Dict[Tuple[str, str], TokenBucket] = {}
        self._lock = threading.Lock()

    def get(self, tenant: str, connector: str, capacity: int, refill_rate_per_sec: float) -> TokenBucket:
        key = (tenant, connector)
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = TokenBucket(capacity=capacity, refill_rate_per_sec=refill_rate_per_sec, tokens=float(capacity), last_refill=time.time())
                self._buckets[key] = b
            return b


@dataclass
class QueueItem:
    enqueued_at: float
    tenant: str
    connector: str
    fn: Callable[[], Any]
    deadline_ts: float


class RateLimiter:
    def __init__(self, capacity: int = 10, refill_rate_per_sec: float = 5.0, ttl_seconds: int = 60) -> None:
        self.capacity = capacity
        self.refill = refill_rate_per_sec
        self.ttl = ttl_seconds
        self.registry = BucketRegistry()
        self.queues: Dict[Tuple[str, str], Deque[QueueItem]] = defaultdict(deque)
        # KPIs
        self.total_requests = 0
        self.rate_limited = 0
        self.errors_5xx = 0
        self.wait_times: list[float] = []
        self.step_latencies: list[float] = []
        self.dlq_dropped_total: int = 0

    def consume_or_queue(self, tenant: str, connector: str, fn: Callable[[], Any]) -> Tuple[str, Optional[Any]]:
        """Try to consume a token; if unavailable, enqueue and return ('queued', None).
        When executed, returns ('ok', result). If item expired, returns ('dlq', None).
        """
        self.total_requests += 1
        bucket = self.registry.get(tenant, connector, self.capacity, self.refill)
        now = time.time()
        if bucket.try_consume(1.0, now):
            start = time.perf_counter()
            try:
                res = fn()
            except Exception:
                self.errors_5xx += 1
                raise
            finally:
                self.step_latencies.append(max(0.0, time.perf_counter() - start))
            return 'ok', res
        # No tokens: enqueue with TTL
        self.rate_limited += 1
        qi = QueueItem(enqueued_at=now, tenant=tenant, connector=connector, fn=fn, deadline_ts=now + self.ttl)
        self.queues[(tenant, connector)].append(qi)
        return 'queued', None

    def process(self, max_items: int = 100) -> Tuple[int, int]:
        """Attempt to process queued items across all queues using available tokens.
        Returns (processed, dead_lettered)."""
        processed = 0
        dead = 0
        now = time.time()
        for key, q in list(self.queues.items()):
            tenant, connector = key
            bucket = self.registry.get(tenant, connector, self.capacity, self.refill)
            # Pop until tokens exhausted or queue empty
            while q and processed < max_items:
                item = q[0]
                if now >= item.deadline_ts:
                    q.popleft()
                    dead += 1
                    self.dlq_dropped_total += 1
                    continue
                # Try after a fresh refill tick
                bucket.refill()
                if not bucket.try_consume(1.0):
                    break
                # Got token; process
                q.popleft()
                start_wait = item.enqueued_at
                self.wait_times.append(max(0.0, time.time() - start_wait))
                start = time.perf_counter()
                try:
                    item.fn()
                except Exception:
                    self.errors_5xx += 1
                finally:
                    self.step_latencies.append(max(0.0, time.perf_counter() - start))
                processed += 1
            if not q:
                # remove empty queue to avoid memory leak
                self.queues.pop(key, None)
        return processed, dead

    @staticmethod
    def backoff_with_jitter(base: float, attempt: int) -> float:
        return base * (2 ** attempt) + random.uniform(0, base)

    def kpis(self) -> Dict[str, Any]:
        total = max(1, self.total_requests)
        p95 = 0.0
        if self.step_latencies:
            arr = sorted(self.step_latencies)
            idx = max(0, int(0.95 * len(arr)) - 1)
            p95 = arr[idx]
        avg_wait = (sum(self.wait_times) / len(self.wait_times)) if self.wait_times else 0.0
        dlq_depth = sum(len(q) for q in self.queues.values())
        return {
            'rate_limited_pct': self.rate_limited / total,
            'errors_5xx_pct': self.errors_5xx / total,
            'avg_wait_to_execute': avg_wait,
            'dlq_depth': dlq_depth,
            'p95_step_latency': p95,
            'dlq_total': self.dlq_dropped_total,
        }

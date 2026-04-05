from __future__ import annotations

import time

from src.core.rate_limit import RateLimiter


def test_rate_limiter_queue_and_process():
    rl = RateLimiter(capacity=1, refill_rate_per_sec=100.0, ttl_seconds=1)
    outputs = []

    def work(x):
        outputs.append(x)

    # First consumes immediately
    status, res = rl.consume_or_queue('t1','connA', lambda: work(1))
    assert status == 'ok'
    # Second should queue
    status2, _ = rl.consume_or_queue('t1','connA', lambda: work(2))
    assert status2 == 'queued'
    # Allow brief time for refill, then process queue
    time.sleep(0.02)
    p, d = rl.process()
    assert p >= 1
    assert d == 0
    assert outputs == [1,2]


def test_rate_limiter_dead_letter():
    rl = RateLimiter(capacity=0, refill_rate_per_sec=0.0, ttl_seconds=0)  # force DLQ
    status, _ = rl.consume_or_queue('t1','connA', lambda: None)
    assert status == 'queued'
    p, d = rl.process()
    assert p == 0 and d >= 1


def test_rate_limiter_kpis_and_backoff():
    rl = RateLimiter(capacity=1, refill_rate_per_sec=0.1, ttl_seconds=1)
    # one ok
    rl.consume_or_queue('t1','connA', lambda: None)
    # one queued (rate limited)
    rl.consume_or_queue('t1','connA', lambda: None)
    rl.process()
    k = rl.kpis()
    assert 'rate_limited_pct' in k and 'p95_step_latency' in k and 'dlq_depth' in k
    # backoff grows with attempt
    b1 = rl.backoff_with_jitter(0.1, 1)
    b2 = rl.backoff_with_jitter(0.1, 2)
    assert b2 > b1

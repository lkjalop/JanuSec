import time

import pytest

from src.core.dedup.dedup_service import DedupService


def test_reserve_and_seen_and_stats():
    svc = DedupService(ttl_seconds=0.5, cleanup_interval=0.1)
    key = 'k1'
    first = svc.reserve(key)
    assert first is True
    # second immediate reserve should be suppressed
    second = svc.reserve(key)
    assert second is False
    assert svc.seen(key) is True
    s = svc.stats()
    assert s['reservations'] >= 1
    assert s['suppressed'] >= 1


def test_ttl_expiry():
    svc = DedupService(ttl_seconds=0.2, cleanup_interval=0.05)
    key = 'expire-me'
    assert svc.reserve(key) is True
    assert svc.seen(key) is True
    # wait longer than TTL
    time.sleep(0.35)
    # cleanup thread should have removed the key (or seen() returns False after TTL)
    assert svc.seen(key) is False


def test_concurrent_reserve():
    svc = DedupService(ttl_seconds=5.0, cleanup_interval=1.0)
    key = 'concurrent-key'
    results = []

    def worker():
        results.append(svc.reserve(key))

    import threading
    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one thread should have received True (first reservation), others False
    trues = sum(1 for r in results if r)
    falses = sum(1 for r in results if not r)
    assert trues == 1
    assert falses == len(results) - 1

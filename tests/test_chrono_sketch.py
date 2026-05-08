"""Unit tests for src/core/chrono/sketch_store.py — ChronoGraph."""
import math
import os
import tempfile
import time

import pytest

# Use a fresh store for each test — don't pollute CHRONO singleton
from src.core.chrono.sketch_store import ChronoSketchStore, _bucket_epoch, BUCKET_SECONDS


@pytest.fixture()
def store():
    return ChronoSketchStore()


class TestBucketEpoch:
    def test_floors_to_hour(self):
        ts = 1735729200.0 + 1800  # 30 min past an hour boundary
        bk = _bucket_epoch(ts)
        assert bk == 1735729200  # == floor to boundary
        assert bk % BUCKET_SECONDS == 0

    def test_same_hour_same_bucket(self):
        t1 = 1735729200.0
        t2 = 1735729200.0 + 3599.9
        assert _bucket_epoch(t1) == _bucket_epoch(t2)

    def test_different_hours_different_buckets(self):
        t1 = 1735729200.0
        t2 = 1735729200.0 + 3600
        assert _bucket_epoch(t1) != _bucket_epoch(t2)


class TestIncrement:
    def test_simple_accumulation(self, store):
        now = time.time()
        store.increment("user", "alice", "events", 5.0, ts=now)
        store.increment("user", "alice", "events", 3.0, ts=now)
        total = store.window_sum("user", "alice", "events", now - 3600, now + 3600)
        assert total == 8.0

    def test_separate_metrics(self, store):
        now = time.time()
        store.increment("user", "alice", "events", 5.0, ts=now)
        store.increment("user", "alice", "bytes_out", 1000.0, ts=now)
        assert store.window_sum("user", "alice", "events", now - 3600, now + 3600) == 5.0
        assert store.window_sum("user", "alice", "bytes_out", now - 3600, now + 3600) == 1000.0

    def test_separate_entities(self, store):
        now = time.time()
        store.increment("user", "alice", "events", 10.0, ts=now)
        store.increment("user", "bob", "events", 20.0, ts=now)
        assert store.window_sum("user", "alice", "events", now - 3600, now + 3600) == 10.0
        assert store.window_sum("user", "bob", "events", now - 3600, now + 3600) == 20.0

    def test_missing_entity_returns_zero(self, store):
        now = time.time()
        assert store.window_sum("user", "nobody", "events", now - 3600, now + 3600) == 0.0

    def test_empty_entity_id_ignored(self, store):
        store.increment("user", "", "events", 5.0)
        assert store.size() == 0


class TestWindowSum:
    def test_excludes_out_of_window(self, store):
        now = time.time()
        store.increment("user", "alice", "events", 5.0, ts=now - 2 * 3600)  # 2h ago
        store.increment("user", "alice", "events", 3.0, ts=now)             # now
        # 1h window: should only capture the "now" bucket
        total = store.window_sum("user", "alice", "events", now - 3600, now + 3600)
        assert total == 3.0

    def test_multiple_buckets_summed(self, store):
        now = time.time()
        for i in range(5):
            store.increment("user", "alice", "events", 1.0, ts=now - i * 3600)
        total = store.window_sum("user", "alice", "events", now - 5 * 3600, now + 3600)
        assert total == 5.0


class TestZScore:
    def test_insufficient_samples_returns_zero(self, store):
        now = time.time()
        store.increment("user", "alice", "events", 5.0, ts=now)
        z = store.z_score("user", "alice", "events", window_seconds=3600)
        assert z["samples"] < 2
        assert z["z"] == 0.0
        assert z["anomaly"] is False

    def test_anomaly_detected(self, store):
        now = time.time()
        # Build historical baseline with slight variance (0.5–1.5/hr, avg ~1.0, stddev > 0)
        baseline = [0.5, 1.0, 1.5, 1.0, 0.5, 1.5, 1.0, 0.5, 1.5, 1.0,
                    0.5, 1.0, 1.5, 1.0, 0.5, 1.5, 1.0, 0.5, 1.5, 1.0,
                    0.5, 1.0, 1.5, 1.0]
        for i, val in enumerate(baseline, start=2):
            store.increment("user", "alice", "events", val, ts=now - i * 3600)
        # Current window (last 1h) has a spike of 100
        store.increment("user", "alice", "events", 100.0, ts=now)
        z = store.z_score("user", "alice", "events", window_seconds=3600, current_value=100.0)
        assert z["z"] > 2.0
        assert z["anomaly"] is True

    def test_missing_entity_returns_zero_z(self, store):
        z = store.z_score("user", "nobody", "events", window_seconds=3600)
        assert z["z"] == 0.0


class TestTopEntities:
    def test_ordering(self, store):
        now = time.time()
        store.increment("user", "alice", "events", 10.0, ts=now)
        store.increment("user", "bob", "events", 50.0, ts=now)
        store.increment("user", "carol", "events", 30.0, ts=now)
        top = store.top_entities("user", "events", 86400, n=3)
        assert top[0][0] == "bob"
        assert top[1][0] == "carol"
        assert top[2][0] == "alice"

    def test_limit_respected(self, store):
        now = time.time()
        for i in range(10):
            store.increment("user", f"user{i}", "events", float(i), ts=now)
        top = store.top_entities("user", "events", 86400, n=3)
        assert len(top) == 3


class TestEntityMetrics:
    def test_returns_all_metrics(self, store):
        now = time.time()
        store.increment("user", "alice", "events", 5.0, ts=now)
        store.increment("user", "alice", "bytes_out", 1000.0, ts=now)
        m = store.entity_metrics("user", "alice", window_seconds=86400)
        assert "events" in m
        assert "bytes_out" in m
        assert m["events"]["window_sum"] == 5.0

    def test_empty_entity_returns_empty(self, store):
        m = store.entity_metrics("user", "nobody", window_seconds=86400)
        assert m == {}


class TestPersistence:
    def test_save_and_load_roundtrip(self, store):
        now = time.time()
        store.increment("user", "alice", "events", 42.0, ts=now)
        store.increment("user", "bob", "bytes_out", 1e6, ts=now)

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            n_saved = store.save(db_path)
            assert n_saved >= 2  # at least the two buckets written

            store2 = ChronoSketchStore()
            n_loaded = store2.load(db_path)
            assert n_loaded >= 2

            alice_sum = store2.window_sum("user", "alice", "events", now - 3600, now + 3600)
            assert alice_sum == 42.0
            bob_sum = store2.window_sum("user", "bob", "bytes_out", now - 3600, now + 3600)
            assert bob_sum == 1e6
        finally:
            os.unlink(db_path)

    def test_load_nonexistent_file_returns_zero(self, store):
        n = store.load("/tmp/does_not_exist_chrono_test.db")
        assert n == 0

    def test_save_prunes_old_buckets(self, store):
        # Add a very old bucket (40 days ago) — should be pruned on save
        old_ts = time.time() - 40 * 86400
        store.increment("user", "alice", "events", 99.0, ts=old_ts)

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            n_saved = store.save(db_path)
            # The old bucket should be pruned (0 rows written beyond lookback)
            assert n_saved == 0
        finally:
            os.unlink(db_path)

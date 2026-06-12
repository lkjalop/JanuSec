"""Tests for ChronoGraph data-time windowing + population fallback.

Two structural fixes:
  P0 — z_score windows on a caller-supplied reference_ts (the data's max event time),
       not wall-clock now. Without this, historical-log assessments score every entity's
       *empty* current window against its history → all z-scores meaningless.
  P1 — when an entity has < 2 historical buckets, fall back to a leave-one-out population
       z-score (this entity vs its peers in the current data) so anomalies surface on the
       very first assessment.
"""
from __future__ import annotations

import random

from src.core.chrono.sketch_store import ChronoSketchStore

HOUR = 3600
DAY = 86400
# A historical anchor far from wall-clock now (≈ Feb 2025), to prove the window follows
# the data, not the clock.
HIST = 1738368000.0


class TestDataTimeWindowing:
    def test_historical_spike_detected(self):
        random.seed(1)
        store = ChronoSketchStore()
        for d in range(27):
            for _ in range(random.randint(3, 7)):
                store.increment("user", "alice", "events", 1.0, ts=HIST + d * DAY + HOUR)
        for _ in range(60):
            store.increment("user", "alice", "events", 1.0, ts=HIST + 27 * DAY + 12 * HOUR)
        ref = HIST + 27 * DAY + 23 * HOUR
        z = store.z_score("user", "alice", "events", window_seconds=12 * HOUR, reference_ts=ref)
        assert z["current"] == 60
        assert z["source"] == "temporal"
        assert z["anomaly"] is True
        assert z["z"] > 5

    def test_wall_clock_now_misses_historical_data(self):
        # The old default (reference_ts=None → now) puts all historical data outside the
        # window → current sum 0 → no real anomaly. This documents WHY the param exists.
        store = ChronoSketchStore()
        for d in range(10):
            store.increment("user", "bob", "events", 5.0, ts=HIST + d * DAY)
        z = store.z_score("user", "bob", "events", window_seconds=DAY, reference_ts=None)
        assert z["current"] == 0  # nothing in the wall-clock window


class TestPopulationFallback:
    def _peers_plus_outlier(self, store, ref):
        random.seed(2)
        for u in ("u1", "u2", "u3", "u4", "u5"):
            for _ in range(random.randint(2, 5)):
                store.increment("user", u, "events", 1.0, ts=ref)
        for _ in range(40):
            store.increment("user", "intruder", "events", 1.0, ts=ref)

    def test_outlier_flagged_against_peers(self):
        store = ChronoSketchStore()
        ref = HIST + 10 * DAY
        self._peers_plus_outlier(store, ref)
        z = store.z_score("user", "intruder", "events", window_seconds=DAY, reference_ts=ref)
        assert z["source"] == "population"
        assert z["anomaly"] is True
        assert z["samples"] == 5  # leave-one-out: 5 peers, not 6

    def test_normal_peer_not_flagged(self):
        store = ChronoSketchStore()
        ref = HIST + 10 * DAY
        self._peers_plus_outlier(store, ref)
        z = store.z_score("user", "u1", "events", window_seconds=DAY, reference_ts=ref)
        assert z["source"] == "population"
        assert z["anomaly"] is False

    def test_no_fallback_when_too_few_peers(self):
        store = ChronoSketchStore()
        ref = HIST + 10 * DAY
        store.increment("user", "solo", "events", 9.0, ts=ref)
        z = store.z_score("user", "solo", "events", window_seconds=DAY, reference_ts=ref)
        # < 3 peers → no population score; stays temporal-sparse (no false anomaly)
        assert z["source"] in ("temporal_sparse", "temporal")
        assert z["anomaly"] is False

    def test_population_disabled(self):
        store = ChronoSketchStore()
        ref = HIST + 10 * DAY
        self._peers_plus_outlier(store, ref)
        z = store.z_score("user", "intruder", "events", window_seconds=DAY,
                          reference_ts=ref, allow_population=False)
        assert z["source"] != "population"

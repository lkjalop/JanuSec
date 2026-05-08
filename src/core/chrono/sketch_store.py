"""ChronoGraph — append-only time-bucketed accumulator.

Each (entity_type, entity_id, metric) triple gets a ring of 1-hour buckets
covering a configurable lookback window (default 30 days = 720 buckets).

Public API
----------
CHRONO.increment(entity_type, entity_id, metric, value, ts=None)
    Add `value` to the bucket for the hour that contains `ts`
    (defaults to now).

CHRONO.window_sum(entity_type, entity_id, metric, start_ts, end_ts)
    Sum all bucket values within [start_ts, end_ts].

CHRONO.window_mean_hourly(entity_type, entity_id, metric, window_seconds)
    Mean per-hour value over the last `window_seconds` from now.

CHRONO.z_score(entity_type, entity_id, metric, window_seconds=86400*7,
               current_value=None)
    Z-score of the current window sum vs historical buckets outside that
    window (up to LOOKBACK_SECONDS).  Returns dict with z, mean, stddev,
    anomaly flag.

CHRONO.top_entities(entity_type, metric, window_seconds, n=10)
    Return top-N (entity_id, sum) sorted descending for the window.

CHRONO.snapshot(entity_type, entity_id, metric)
    Raw dict: {bucket_epoch: value, ...} for inspection / serialisation.
"""
from __future__ import annotations

import math
import os
import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# ── Constants ─────────────────────────────────────────────────────────────────
BUCKET_SECONDS: int = 3600                              # 1-hour buckets
LOOKBACK_SECONDS: int = int(os.getenv(
    "JANUSEC_CHRONO_LOOKBACK_DAYS", "30"
)) * 86400                                              # ring depth
MAX_ENTITIES: int = int(os.getenv("JANUSEC_CHRONO_MAX_ENTITIES", "50000"))


def _bucket_epoch(ts: float) -> int:
    """Floor ts to the nearest hour boundary."""
    return int(ts // BUCKET_SECONDS) * BUCKET_SECONDS


class _EntityMetricBuckets:
    """Ring buffer of hourly buckets for one (entity, metric) pair."""

    __slots__ = ("_buckets", "_lock")

    def __init__(self) -> None:
        self._buckets: Dict[int, float] = {}
        self._lock = threading.Lock()

    def add(self, value: float, ts: float) -> None:
        bk = _bucket_epoch(ts)
        with self._lock:
            self._buckets[bk] = self._buckets.get(bk, 0.0) + value
            # Evict buckets older than LOOKBACK_SECONDS
            cutoff = _bucket_epoch(ts) - LOOKBACK_SECONDS
            stale = [k for k in self._buckets if k < cutoff]
            for k in stale:
                del self._buckets[k]

    def sum_window(self, start_ts: float, end_ts: float) -> float:
        start_bk = _bucket_epoch(start_ts)
        end_bk = _bucket_epoch(end_ts)
        with self._lock:
            return sum(
                v for bk, v in self._buckets.items()
                if start_bk <= bk <= end_bk
            )

    def z_score(
        self,
        window_seconds: float,
        current_value: Optional[float] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        window_start = now - window_seconds
        # Historical buckets are those *outside* the current window
        with self._lock:
            current_sum = sum(
                v for bk, v in self._buckets.items()
                if bk >= _bucket_epoch(window_start)
            )
            hist_values = [
                v for bk, v in self._buckets.items()
                if bk < _bucket_epoch(window_start)
            ]

        if current_value is None:
            current_value = current_sum

        n = len(hist_values)
        if n < 2:
            return {
                "z": 0.0, "mean": 0.0, "stddev": 0.0,
                "samples": n, "current": current_value, "anomaly": False,
            }

        mean = sum(hist_values) / n
        variance = sum((x - mean) ** 2 for x in hist_values) / n
        stddev = math.sqrt(variance)

        z = (current_value - mean) / stddev if stddev > 0 else 0.0
        return {
            "z": round(z, 3),
            "mean": round(mean, 3),
            "stddev": round(stddev, 3),
            "samples": n,
            "current": round(current_value, 3),
            "anomaly": abs(z) >= 2.5,
        }

    def snapshot(self) -> Dict[int, float]:
        with self._lock:
            return dict(self._buckets)

    def total_sum(self) -> float:
        with self._lock:
            return sum(self._buckets.values())


class ChronoSketchStore:
    """Global singleton accumulating time-bucketed entity metrics.

    Thread-safe.  No external dependencies.  Survives across multiple
    assessment ingest calls within a single server process lifetime.
    Optionally persists to a JSON file on eviction / shutdown.
    """

    def __init__(self) -> None:
        # _store[(entity_type, entity_id, metric)] -> _EntityMetricBuckets
        self._store: Dict[Tuple[str, str, str], _EntityMetricBuckets] = {}
        self._lock = threading.Lock()

    # ── Write ─────────────────────────────────────────────────────────────────

    def increment(
        self,
        entity_type: str,
        entity_id: str,
        metric: str,
        value: float,
        *,
        ts: Optional[float] = None,
    ) -> None:
        if not entity_id or not entity_type or not metric:
            return
        if ts is None:
            ts = time.time()
        key = (entity_type, entity_id, metric)
        with self._lock:
            if key not in self._store:
                if len(self._store) >= MAX_ENTITIES:
                    return  # cap — don't blow up memory
                self._store[key] = _EntityMetricBuckets()
            emb = self._store[key]
        emb.add(value, ts)

    # ── Read ──────────────────────────────────────────────────────────────────

    def window_sum(
        self,
        entity_type: str,
        entity_id: str,
        metric: str,
        start_ts: float,
        end_ts: float,
    ) -> float:
        key = (entity_type, entity_id, metric)
        with self._lock:
            emb = self._store.get(key)
        return emb.sum_window(start_ts, end_ts) if emb else 0.0

    def window_mean_hourly(
        self,
        entity_type: str,
        entity_id: str,
        metric: str,
        window_seconds: float,
    ) -> float:
        now = time.time()
        total = self.window_sum(entity_type, entity_id, metric, now - window_seconds, now)
        n_hours = max(1, window_seconds / BUCKET_SECONDS)
        return total / n_hours

    def z_score(
        self,
        entity_type: str,
        entity_id: str,
        metric: str,
        window_seconds: float = 86400 * 7,
        current_value: Optional[float] = None,
    ) -> Dict[str, Any]:
        key = (entity_type, entity_id, metric)
        with self._lock:
            emb = self._store.get(key)
        if emb is None:
            return {
                "z": 0.0, "mean": 0.0, "stddev": 0.0,
                "samples": 0, "current": current_value or 0.0, "anomaly": False,
            }
        return emb.z_score(window_seconds, current_value)

    def top_entities(
        self,
        entity_type: str,
        metric: str,
        window_seconds: float,
        n: int = 10,
    ) -> List[Tuple[str, float]]:
        now = time.time()
        start = now - window_seconds
        results: List[Tuple[str, float]] = []
        with self._lock:
            keys = [k for k in self._store if k[0] == entity_type and k[2] == metric]
            pairs = [(k[1], self._store[k]) for k in keys]
        for entity_id, emb in pairs:
            s = emb.sum_window(start, now)
            if s > 0:
                results.append((entity_id, s))
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:n]

    def snapshot(
        self,
        entity_type: str,
        entity_id: str,
        metric: str,
    ) -> Dict[int, float]:
        key = (entity_type, entity_id, metric)
        with self._lock:
            emb = self._store.get(key)
        return emb.snapshot() if emb else {}

    def entity_metrics(
        self,
        entity_type: str,
        entity_id: str,
        window_seconds: float = 86400 * 7,
    ) -> Dict[str, Dict[str, Any]]:
        """Return all metrics for one entity with z-scores — for TemporalRAG context."""
        out: Dict[str, Dict[str, Any]] = {}
        now = time.time()
        start = now - window_seconds
        with self._lock:
            keys = [k for k in self._store if k[0] == entity_type and k[1] == entity_id]
            pairs = [(k[2], self._store[k]) for k in keys]
        for metric, emb in pairs:
            wsum = emb.sum_window(start, now)
            zdata = emb.z_score(window_seconds)
            out[metric] = {
                "window_sum": round(wsum, 2),
                **zdata,
            }
        return out

    def size(self) -> int:
        with self._lock:
            return len(self._store)

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: str) -> int:
        """Flush all buckets to a SQLite file.  Returns row count written."""
        import sqlite3
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self._lock:
            snapshot = {
                key: emb.snapshot()
                for key, emb in self._store.items()
            }
        rows_written = 0
        try:
            con = sqlite3.connect(path, timeout=10)
            con.execute("""
                CREATE TABLE IF NOT EXISTS chrono_buckets (
                    entity_type TEXT NOT NULL,
                    entity_id   TEXT NOT NULL,
                    metric      TEXT NOT NULL,
                    bucket_ts   INTEGER NOT NULL,
                    value       REAL NOT NULL,
                    PRIMARY KEY (entity_type, entity_id, metric, bucket_ts)
                )
            """)
            con.execute("CREATE INDEX IF NOT EXISTS idx_chrono_entity ON chrono_buckets(entity_type, entity_id)")
            cutoff = int(time.time()) - LOOKBACK_SECONDS
            rows: list[tuple] = []
            for (etype, eid, metric), buckets in snapshot.items():
                for bk, val in buckets.items():
                    if bk >= cutoff and val > 0:
                        rows.append((etype, eid, metric, bk, val))
            con.executemany(
                "INSERT OR REPLACE INTO chrono_buckets VALUES (?,?,?,?,?)", rows
            )
            # Prune stale rows
            con.execute("DELETE FROM chrono_buckets WHERE bucket_ts < ?", (cutoff,))
            con.commit()
            con.close()
            rows_written = len(rows)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("ChronoGraph save failed: %s", exc)
        return rows_written

    def load(self, path: str) -> int:
        """Load buckets from SQLite.  Merges into in-memory state (additive).
        Returns row count loaded."""
        import sqlite3
        if not os.path.exists(path):
            return 0
        rows_loaded = 0
        try:
            con = sqlite3.connect(path, timeout=10)
            con.row_factory = sqlite3.Row
            cutoff = int(time.time()) - LOOKBACK_SECONDS
            cur = con.execute(
                "SELECT entity_type, entity_id, metric, bucket_ts, value "
                "FROM chrono_buckets WHERE bucket_ts >= ?",
                (cutoff,),
            )
            for row in cur:
                key = (row["entity_type"], row["entity_id"], row["metric"])
                with self._lock:
                    if key not in self._store:
                        if len(self._store) >= MAX_ENTITIES:
                            continue
                        self._store[key] = _EntityMetricBuckets()
                    emb = self._store[key]
                # Directly merge without calling add() to avoid re-eviction
                with emb._lock:
                    bk = int(row["bucket_ts"])
                    emb._buckets[bk] = emb._buckets.get(bk, 0.0) + float(row["value"])
                rows_loaded += 1
            con.close()
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("ChronoGraph load failed: %s", exc)
        return rows_loaded

    def start_autosave(self, path: str, interval_seconds: int = 300) -> None:
        """Start a daemon thread that flushes to SQLite every `interval_seconds`."""
        def _loop() -> None:
            import logging
            _log = logging.getLogger(__name__)
            while True:
                time.sleep(interval_seconds)
                try:
                    n = self.save(path)
                    _log.debug("ChronoGraph autosave: %d rows -> %s", n, path)
                except Exception as exc:
                    _log.warning("ChronoGraph autosave error: %s", exc)

        t = threading.Thread(target=_loop, daemon=True, name="chrono-autosave")
        t.start()


# ── Singleton + startup persistence ───────────────────────────────────────────
CHRONO = ChronoSketchStore()

_CHRONO_DB_PATH: str = os.getenv(
    "JANUSEC_CHRONO_DB",
    os.path.join(os.getenv("SESSION_PERSIST_DIR", "data/sessions"), "chrono.db"),
)

def _init_persistence() -> None:
    """Load existing buckets and start autosave.  Called once at import time."""
    try:
        n = CHRONO.load(_CHRONO_DB_PATH)
        if n:
            import logging
            logging.getLogger(__name__).info(
                "ChronoGraph: loaded %d buckets from %s", n, _CHRONO_DB_PATH
            )
        interval = int(os.getenv("JANUSEC_CHRONO_AUTOSAVE_S", "300"))
        CHRONO.start_autosave(_CHRONO_DB_PATH, interval_seconds=interval)
    except Exception:
        pass  # persistence is best-effort; never block startup


_init_persistence()

__all__ = ["CHRONO", "ChronoSketchStore"]

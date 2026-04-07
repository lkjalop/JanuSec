"""
Feedback Anomaly Detector (CB-5)
Detects potential feedback-poisoning attacks by monitoring the rate at which
analysts flip verdicts from MALICIOUS → BENIGN within a sliding 24-hour window.

When the flip rate for a given (tenant, analyst) pair exceeds ALERT_THRESHOLD,
the detector returns is_anomaly=True so callers can emit a security alert.

Backend: in-memory dict (no external deps required).  If REDIS_URL is set and
redis-py is available an optional Redis fallback can be wired in future.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections import defaultdict, deque
from typing import NamedTuple

logger = logging.getLogger(__name__)

# Configurable via env vars
ALERT_THRESHOLD = float(os.getenv('FEEDBACK_FLIP_THRESHOLD', '0.15'))
WINDOW_HOURS = float(os.getenv('FEEDBACK_FLIP_WINDOW_HOURS', '24'))
_WINDOW_SECONDS = WINDOW_HOURS * 3600


class FlipEvent(NamedTuple):
    ts: float           # epoch seconds
    from_verdict: str
    to_verdict: str


class FeedbackAnomalyDetector:
    """Sliding-window flip-rate anomaly detector (thread-safe)."""

    def __init__(
        self,
        alert_threshold: float = ALERT_THRESHOLD,
        window_seconds: float = _WINDOW_SECONDS,
    ) -> None:
        self.alert_threshold = alert_threshold
        self.window_seconds = window_seconds
        # {tenant_id: {analyst_tag: deque[FlipEvent]}}
        self._store: dict[str, dict[str, deque[FlipEvent]]] = defaultdict(
            lambda: defaultdict(deque)
        )
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_flip(
        self,
        tenant_id: str,
        analyst_tag: str,
        from_verdict: str,
        to_verdict: str,
        ts: float | None = None,
    ) -> None:
        """Record a verdict flip event for a given (tenant, analyst) pair."""
        now = ts if ts is not None else time.time()
        event = FlipEvent(ts=now, from_verdict=from_verdict.upper(), to_verdict=to_verdict.upper())
        with self._lock:
            queue = self._store[tenant_id][analyst_tag]
            queue.append(event)
            self._prune(queue, now)

    def check_for_poisoning(
        self,
        tenant_id: str,
        analyst_tag: str,
    ) -> tuple[bool, float]:
        """Return (is_anomaly, flip_rate) for the given (tenant, analyst) pair.

        flip_rate is the fraction of MALICIOUS→BENIGN events in the window vs
        all feedback events recorded.
        """
        now = time.time()
        with self._lock:
            queue = self._store[tenant_id].get(analyst_tag)
            if queue is None:
                return False, 0.0
            self._prune(queue, now)
            events = list(queue)

        if not events:
            return False, 0.0

        mal_to_benign = sum(
            1 for e in events
            if e.from_verdict in ('MALICIOUS', 'HIGH', 'CRITICAL')
            and e.to_verdict in ('BENIGN', 'CLEAN', 'FALSE_POSITIVE', 'FP')
        )
        flip_rate = mal_to_benign / len(events)
        is_anomaly = flip_rate >= self.alert_threshold

        if is_anomaly:
            logger.warning(
                'feedback_anomaly: poisoning suspected tenant=%s analyst=%s '
                'flip_rate=%.2f threshold=%.2f window_events=%d',
                tenant_id,
                analyst_tag,
                flip_rate,
                self.alert_threshold,
                len(events),
            )

        return is_anomaly, flip_rate

    def get_stats(self, tenant_id: str) -> dict[str, dict]:
        """Return all current window events per analyst for audit purposes."""
        now = time.time()
        out: dict[str, dict] = {}
        with self._lock:
            for analyst_tag, queue in self._store.get(tenant_id, {}).items():
                self._prune(queue, now)
                events = list(queue)
                out[analyst_tag] = {
                    'total': len(events),
                    'events': [
                        {'ts': e.ts, 'from': e.from_verdict, 'to': e.to_verdict}
                        for e in events
                    ],
                }
        return out

    def reset(self, tenant_id: str | None = None) -> None:
        """Clear state (useful for tests)."""
        with self._lock:
            if tenant_id:
                self._store.pop(tenant_id, None)
            else:
                self._store.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prune(self, queue: deque[FlipEvent], now: float) -> None:
        """Remove events older than the window (called under lock)."""
        cutoff = now - self.window_seconds
        while queue and queue[0].ts < cutoff:
            queue.popleft()


# Module-level singleton used by wired call sites
_detector = FeedbackAnomalyDetector()


def get_detector() -> FeedbackAnomalyDetector:
    """Return the module-level singleton detector."""
    return _detector

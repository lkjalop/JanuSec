"""Per-assessment ML signal aggregator.

Collects iso_score, ensemble_score, rarity, and EWMA residuals emitted by
ingest_identity_event() across every event in an assessment batch. Provides
per-user summaries that assessment_worker reads back after Stage 5g to elevate
cluster factor_tags and triage_score.

Design constraints:
  - Thread-safe: multiple threads may call record() concurrently.
  - Assessment-scoped: clear() resets all state at assessment start.
  - Zero external deps: no imports beyond stdlib + numpy (optional).
"""
from __future__ import annotations

import math
import threading
from collections import defaultdict
from typing import Dict, List, Optional


class _UserSignals:
    """Running statistics for one identity across an assessment."""

    __slots__ = (
        "iso_scores", "ensemble_scores", "rarities",
        "ewma_residuals", "anomaly_count", "event_count",
        "peak_iso", "peak_ensemble",
    )

    def __init__(self) -> None:
        self.iso_scores: List[float] = []
        self.ensemble_scores: List[float] = []
        self.rarities: List[float] = []
        self.ewma_residuals: List[float] = []
        self.anomaly_count: int = 0
        self.event_count: int = 0
        self.peak_iso: float = 0.0
        self.peak_ensemble: float = 0.0

    def record(self, iso: float, ensemble: float, rarity: float,
               ewma_res: float, is_anomaly: bool) -> None:
        self.iso_scores.append(iso)
        self.ensemble_scores.append(ensemble)
        self.rarities.append(rarity)
        self.ewma_residuals.append(ewma_res)
        self.event_count += 1
        if is_anomaly:
            self.anomaly_count += 1
        if iso > self.peak_iso:
            self.peak_iso = iso
        if ensemble > self.peak_ensemble:
            self.peak_ensemble = ensemble

    def summary(self) -> Dict:
        n = len(self.iso_scores)
        if n == 0:
            return {
                "event_count": 0, "anomaly_count": 0, "anomaly_rate": 0.0,
                "peak_iso": 0.0, "mean_iso": 0.0, "p95_iso": 0.0,
                "peak_ensemble": 0.0, "mean_ensemble": 0.0,
                "mean_rarity": 0.0, "peak_ewma_residual": 0.0,
                "ewma_spike_count": 0,
            }
        iso_sorted = sorted(self.iso_scores)
        p95_idx = max(0, int(n * 0.95) - 1)
        ewma_spikes = sum(1 for r in self.ewma_residuals if abs(r) > 1.5)
        return {
            "event_count": self.event_count,
            "anomaly_count": self.anomaly_count,
            "anomaly_rate": self.anomaly_count / max(1, self.event_count),
            "peak_iso": round(self.peak_iso, 4),
            "mean_iso": round(sum(self.iso_scores) / n, 4),
            "p95_iso": round(iso_sorted[p95_idx], 4),
            "peak_ensemble": round(self.peak_ensemble, 4),
            "mean_ensemble": round(sum(self.ensemble_scores) / max(1, len(self.ensemble_scores)), 4),
            "mean_rarity": round(sum(self.rarities) / max(1, len(self.rarities)), 4),
            "peak_ewma_residual": round(max((abs(r) for r in self.ewma_residuals), default=0.0), 4),
            "ewma_spike_count": ewma_spikes,
        }


class MLSignalAggregator:
    """Thread-safe, assessment-scoped collector of ML anomaly signals.

    Usage pattern in assessment_worker:
        from src.ml.signal_aggregator import ASSESSMENT_ML_SIGNALS
        ASSESSMENT_ML_SIGNALS.clear()               # at assessment start
        # ... Stage 5g runs ingest_identity_event() with aggregator=ASSESSMENT_ML_SIGNALS
        summary = ASSESSMENT_ML_SIGNALS.summary(user)  # after Stage 5g
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._signals: Dict[str, _UserSignals] = defaultdict(_UserSignals)

    def record(
        self,
        user: str,
        iso_score: float,
        ensemble_score: float,
        rarity: float,
        ewma_residual: float = 0.0,
        is_anomaly: bool = False,
    ) -> None:
        """Record ML scores for one event processed for `user`."""
        if not user:
            return
        user = str(user).strip().lower()
        with self._lock:
            self._signals[user].record(
                iso=float(iso_score),
                ensemble=float(ensemble_score),
                rarity=float(rarity),
                ewma_res=float(ewma_residual),
                is_anomaly=bool(is_anomaly),
            )

    def summary(self, user: str) -> Dict:
        """Return aggregated stats for a user. Returns all-zero dict if unknown."""
        user = str(user).strip().lower()
        with self._lock:
            sig = self._signals.get(user)
        return sig.summary() if sig else _UserSignals().summary()

    def anomalous_users(self, iso_threshold: float = 0.60) -> List[str]:
        """Return users whose peak iso_score exceeds threshold."""
        with self._lock:
            return [u for u, s in self._signals.items() if s.peak_iso >= iso_threshold]

    def all_users(self) -> List[str]:
        with self._lock:
            return list(self._signals.keys())

    def to_chrono_metrics(self, chrono: object, ts: float) -> None:
        """Write aggregated ML scores into ChronoGraph so Stage 5j can z-score them.

        Writes `ml:iso_anom_count` and `ml:ensemble_peak` per user so that
        cross-assessment z-score tracking surfaces users with persistent
        ML-detected anomalies even when individual scores are sub-threshold.
        """
        with self._lock:
            items = list(self._signals.items())
        for user, sig in items:
            try:
                if sig.anomaly_count > 0:
                    chrono.increment("user", user, "ml:iso_anom_count",  # type: ignore[attr-defined]
                                     float(sig.anomaly_count), ts=ts)
                if sig.peak_ensemble > 0:
                    chrono.increment("user", user, "ml:ensemble_peak",
                                     sig.peak_ensemble, ts=ts)
            except Exception:
                pass

    def clear(self) -> None:
        """Reset all signals — call at the start of each assessment."""
        with self._lock:
            self._signals = defaultdict(_UserSignals)

    def __len__(self) -> int:
        with self._lock:
            return len(self._signals)


# Module-level singleton shared between assessment_worker and identity_hopgraph
ASSESSMENT_ML_SIGNALS = MLSignalAggregator()

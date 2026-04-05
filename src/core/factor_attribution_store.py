"""In-memory Factor Attribution Snapshot Store (Stage 10)

Persists per-decision risk factor breakdown snapshots so that subsequent
labeling & rolling statistics jobs can derive factor precision, prevalence
and promotion state without re-running historical compositions.

Design Goals:
  * Lightweight: purely in-memory until a DB-backed implementation is added.
  * Append-only ring buffer semantics with soft size cap (configurable via env).
  * Fast lookup by event_id and recent() iteration for batch export.
  * Minimal schema capturing only what downstream stats need.

Environment:
  FACTOR_ATTRIBUTION_MAX=10000  (soft cap; oldest entries dropped when exceeded)

Snapshot Schema (FactorAttributionSnapshot):
  event_id: str
  ts: float (decision timestamp or capture time)
  factors: list[str] (raw factor identifiers from breakdown, excluding meta only if contribution 0 and factor starts with 'risk:')
  breakdown: list[dict] (original normalized breakdown entries)
  score: float (final calibrated score)
  raw_score: float (pre-calibration score)
  confidence: float | None (original decision classifier confidence)
  variance: float | None
  ci95: tuple[float,float] | None

Downstream Planned Usage:
  * Calibration export (raw_score + label + top factors)
  * Rolling factor stats (aggregate factors across labeled snapshots)
  * Promotion state machine (factor prevalence & precision thresholds)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Iterable, Optional, Tuple, Any
import os
import time
import threading


@dataclass
class FactorAttributionSnapshot:
    event_id: str
    ts: float
    factors: List[str]
    breakdown: List[Dict[str, Any]]
    score: float
    raw_score: float | None
    confidence: float | None
    variance: float | None
    ci95: Tuple[float, float] | None


class FactorAttributionStore:
    def __init__(self) -> None:
        self._by_event: Dict[str, FactorAttributionSnapshot] = {}
        self._recent: List[str] = []  # maintain order of insertion for trimming
        self._lock = threading.Lock()

    def _max(self) -> int:
        try:
            return int(os.getenv('FACTOR_ATTRIBUTION_MAX', '10000') or 10000)
        except Exception:
            return 10000

    def add_snapshot(self, snap: FactorAttributionSnapshot) -> None:
        with self._lock:
            exists = snap.event_id in self._by_event
            self._by_event[snap.event_id] = snap
            if not exists:
                self._recent.append(snap.event_id)
            # Trim if exceeding cap (drop oldest 5%)
            cap = self._max()
            if len(self._recent) > cap:
                trim = max(1, cap // 20)  # 5%
                for ev_id in self._recent[:trim]:
                    self._by_event.pop(ev_id, None)
                del self._recent[:trim]

    def get(self, event_id: str) -> Optional[FactorAttributionSnapshot]:
        return self._by_event.get(event_id)

    def recent(self, limit: int = 500) -> List[FactorAttributionSnapshot]:
        with self._lock:
            ids = self._recent[-limit:]
            # return newest first
            return [self._by_event[i] for i in reversed(ids) if i in self._by_event]

    def all(self) -> Iterable[FactorAttributionSnapshot]:  # pragma: no cover (iter convenience)
        with self._lock:
            for ev in list(self._recent):
                snap = self._by_event.get(ev)
                if snap:
                    yield snap


FACTOR_ATTRIBUTIONS = FactorAttributionStore()

__all__ = [
    'FactorAttributionSnapshot',
    'FactorAttributionStore',
    'FACTOR_ATTRIBUTIONS',
]

"""Rolling Factor Statistics Manager (Stage 10)

Aggregates labeled decision snapshots to compute per-factor performance metrics
used for promotion state logic and guardrails.

States (heuristic initial version):
  emerging: fewer than MIN_SUPPORT total labeled occurrences or precision unknown
  candidate: support >= MIN_SUPPORT and precision >= CANDIDATE_PRECISION
  promoted: support >= MIN_PROMOTED_SUPPORT and precision >= PROMOTED_PRECISION

Environment Configuration:
  FACTOR_STATS_MIN_SUPPORT=5
  FACTOR_STATS_CANDIDATE_PRECISION=0.6
  FACTOR_STATS_PROMOTED_PRECISION=0.75
  FACTOR_STATS_MIN_PROMOTED_SUPPORT=20
  FACTOR_STATS_DECAY=0.0   (optional exponential decay per update)

Precision Definition:
  precision = tp / (tp + fp)  (fp includes explicit 'fp' or 'benign')

Labels Mapping:
  tp -> true positive increment
  fp, benign -> false positive increment
  suspicious, escalated -> ignored (do not affect precision yet)

Thread safety: lightweight lock around updates/reads.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Iterable, List
import threading
import os

LABEL_TO_CLASS = {
    'tp': 'tp',
    'fp': 'fp',
    'benign': 'fp',
    'suspicious': 'ignore',
    'escalated': 'ignore',
}


@dataclass
class FactorStats:
    factor: str
    tp: float = 0.0
    fp: float = 0.0
    last_label_ts: float | None = None
    samples: float = 0.0  # total labeled occurrences seen for this factor

    def total(self) -> float:
        return self.tp + self.fp

    def precision(self) -> float | None:
        denom = self.tp + self.fp
        if denom <= 0:
            return None
        return self.tp / denom if denom else None

    def state(self) -> str:
        p = self.precision()
        total = self.total()
        min_support = _env_float('FACTOR_STATS_MIN_SUPPORT', 5)
        cand_p = _env_float('FACTOR_STATS_CANDIDATE_PRECISION', 0.6)
        prom_p = _env_float('FACTOR_STATS_PROMOTED_PRECISION', 0.75)
        min_prom_support = _env_float('FACTOR_STATS_MIN_PROMOTED_SUPPORT', 20)
        if p is None or total < min_support:
            return 'emerging'
        if total >= min_prom_support and p >= prom_p:
            return 'promoted'
        if p >= cand_p:
            return 'candidate'
        return 'emerging'


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)) or default)
    except Exception:
        return default


class FactorStatsManager:
    def __init__(self) -> None:
        self._stats: Dict[str, FactorStats] = {}
        self._lock = threading.Lock()

    def update_from_label(self, factors: Iterable[str], label: str, ts: float) -> None:
        cls = LABEL_TO_CLASS.get(label)
        if cls in {None, 'ignore'}:
            return
        decay = _env_float('FACTOR_STATS_DECAY', 0.0)
        with self._lock:
            for f in factors:
                st = self._stats.get(f)
                if not st:
                    st = FactorStats(factor=f)
                    self._stats[f] = st
                # Optional exponential decay of previous counts
                if decay > 0 and (st.tp > 0 or st.fp > 0):
                    st.tp *= (1.0 - decay)
                    st.fp *= (1.0 - decay)
                # track total labeled samples for guardrail checks
                st.samples += 1.0
                if cls == 'tp':
                    st.tp += 1.0
                elif cls == 'fp':
                    st.fp += 1.0
                st.last_label_ts = ts

    def get_sample_count(self, factor: str) -> float:
        st = self._stats.get(factor)
        return st.samples if st else 0.0

    def get(self, factor: str) -> Optional[FactorStats]:
        return self._stats.get(factor)

    def summary(self) -> List[dict]:
        with self._lock:
            out = []
            for st in self._stats.values():
                out.append({
                    'factor': st.factor,
                    'tp': st.tp,
                    'fp': st.fp,
                    'total': st.total(),
                    'precision': st.precision(),
                    'state': st.state(),
                    'last_label_ts': st.last_label_ts,
                })
            # Sort by state precedence then precision desc
            state_order = {'promoted': 2, 'candidate': 1, 'emerging': 0}
            out.sort(key=lambda d: (state_order.get(d['state'], 0), d['precision'] or 0.0), reverse=True)
            return out


FACTOR_STATS = FactorStatsManager()

__all__ = ['FACTOR_STATS','FactorStats','FactorStatsManager']

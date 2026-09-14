from __future__ import annotations
import os, math, time
from itertools import combinations
from typing import Dict, Tuple, List, Set

try:  # Prometheus optional
    from prometheus_client import Counter, Gauge  # type: ignore
except Exception:  # pragma: no cover
    Counter = Gauge = None  # type: ignore

from src.core.factors.observe_flags import adjust_delta


class CooccurrenceCorrelator:
    """Tracks factor co-occurrence to surface statistically significant pairs.

    Uses pointwise mutual information (PMI) over event-level co-occurrence.
    A correlation factor 'corr:pair_high_pmi' is emitted once per high-PMI pair (cooldown based).
    Memory is bounded via a max pair tracking cap; new unseen pairs beyond the cap are ignored.
    """

    def __init__(self):
        self.enabled = os.getenv('COOCC_ENABLED', '1') not in ('0','false','False')
        self.min_count = int(os.getenv('COOCC_MIN_COUNT','3') or 3)
        self.pmi_threshold = float(os.getenv('COOCC_PMI_THRESHOLD','0.8') or 0.8)
        self.max_pairs = int(os.getenv('COOCC_MAX_PAIRS','50000') or 50000)
        self.cooldown_seconds = int(os.getenv('COOCC_COOLDOWN_SEC','600') or 600)
        self.emit_specific = os.getenv('COOCC_EMIT_SPECIFIC','0') in ('1','true','True')
        self.max_specific = int(os.getenv('COOCC_MAX_SPECIFIC','2000') or 2000)
        self._specific_active = 0
        self.total_events = 0
        self.factor_counts: Dict[str,int] = {}
        self.pair_counts: Dict[Tuple[str,str],int] = {}
        self.last_emit: Dict[Tuple[str,str], float] = {}
        if not hasattr(self.__class__, '_metrics_init'):
            try:  # pragma: no cover - best effort
                if Counter:
                    self.__class__.high_pmi_total = Counter('correlation_cooccurrence_high_pmi_total', 'High PMI factor pair matches')  # type: ignore
                if Gauge:
                    self.__class__.pairs_tracked = Gauge('correlation_cooccurrence_pairs_tracked', 'Number of factor pairs tracked for co-occurrence')  # type: ignore
                self.__class__._metrics_init = True
            except Exception:  # pragma: no cover
                pass

    def _update_metrics(self):  # pragma: no cover - metrics optional
        try:
            if hasattr(self.__class__, 'pairs_tracked'):
                self.__class__.pairs_tracked.set(len(self.pair_counts))  # type: ignore
        except Exception:
            pass

    def ingest(self, event: dict, factors: List[str]) -> Tuple[List[str], float]:
        """Ingest event-level factors; return (new_factors, delta)."""
        if not self.enabled or not factors:
            return [], 0.0
        # Deduplicate within event
        uniq: Set[str] = set(factors)
        if len(uniq) < 2:
            # Need at least a pair
            self.total_events += 1
            for f in uniq:
                self.factor_counts[f] = self.factor_counts.get(f,0) + 1
            return [], 0.0
        self.total_events += 1
        for f in uniq:
            self.factor_counts[f] = self.factor_counts.get(f,0) + 1
        emitted: List[str] = []
        now = time.time()
        for a,b in combinations(sorted(uniq), 2):
            key = (a,b)
            if key not in self.pair_counts:
                if len(self.pair_counts) >= self.max_pairs:
                    # Soft bound: skip new pairs beyond cap
                    continue
                self.pair_counts[key] = 0
            self.pair_counts[key] += 1
            count = self.pair_counts[key]
            if count < self.min_count:
                continue
            # Compute PMI = ln( p(a,b)/(p(a)p(b)) ) using counts / total_events
            ca = self.factor_counts.get(a,0)
            cb = self.factor_counts.get(b,0)
            if ca == 0 or cb == 0:
                continue
            pab = count / self.total_events
            pa = ca / self.total_events
            pb = cb / self.total_events
            # Avoid domain errors
            denom = pa * pb
            if denom <= 0:
                continue
            pmi = math.log(pab / denom)
            if pmi >= self.pmi_threshold:
                last = self.last_emit.get(key)
                if last and (now - last) < self.cooldown_seconds:
                    continue
                self.last_emit[key] = now
                try:  # pragma: no cover
                    if hasattr(self.__class__, 'high_pmi_total'):
                        self.__class__.high_pmi_total.inc()  # type: ignore
                except Exception:
                    pass
                corr_factor = 'corr:pair_high_pmi'
                if self.emit_specific and self._specific_active < self.max_specific:
                    import hashlib
                    h = hashlib.sha1(f"{a}|{b}".encode('utf-8')).hexdigest()[:8]
                    specific = f'corr:pmi:{h}'
                    if specific not in factors and specific not in emitted:
                        emitted.append(specific)
                        self._specific_active += 1
                if corr_factor not in factors and corr_factor not in emitted:
                    emitted.append(corr_factor)
        if emitted:
            self._update_metrics()
            # Single delta for all emitted (should usually be 1)
            delta = adjust_delta('corr:pair_high_pmi', 0.015)
            return emitted, delta
        self._update_metrics()
        return [], 0.0


GLOBAL_COOCCURRENCE_CORRELATOR = CooccurrenceCorrelator()


def record_cooccurrence_correlation(event: dict, factors: List[str]) -> Tuple[List[str], float]:
    try:
        return GLOBAL_COOCCURRENCE_CORRELATOR.ingest(event, factors)
    except Exception:
        return [], 0.0


__all__ = [
    'CooccurrenceCorrelator',
    'GLOBAL_COOCCURRENCE_CORRELATOR',
    'record_cooccurrence_correlation'
]

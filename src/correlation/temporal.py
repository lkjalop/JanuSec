from __future__ import annotations
import os, time
from collections import deque, defaultdict
from typing import Deque, List, Set, Tuple, Dict, Iterable, Optional

try:
    from prometheus_client import Counter, Gauge  # type: ignore
except Exception:  # pragma: no cover
    Counter = Gauge = None  # type: ignore

from src.core.factors.observe_flags import adjust_delta  # reuse delta shaping

class TemporalCorrelator:
    """Temporal multi-hop pattern correlator.

    Maintains per-entity deque of (timestamp, factor_set) limited by time window & max events.
    Matches ordered patterns (list of steps). Each step: set of acceptable factors (ANY match).
    Current built-in pattern: rare_lineage -> endpoint:lsass_access -> net:beacon_periodic
    Emits single factor: corr:multi_stage_lateral_beacon (small confidence delta add-on) once per sequence.
    """

    def __init__(self):
        self.window_seconds = int(os.getenv('CORR_TEMPORAL_WINDOW_SEC','900') or 900)
        self.max_events_per_entity = int(os.getenv('CORR_TEMPORAL_MAX_EVENTS','200') or 200)
        self.cooldown_seconds = int(os.getenv('CORR_TEMPORAL_COOLDOWN_SEC','300') or 300)
        # Pattern definition (list of frozensets)
        pattern = [
            frozenset({'endpoint:rare_lineage','rare_lineage'}),
            frozenset({'endpoint:lsass_access','lsass_access'}),
            frozenset({'net:beacon_periodic'})
        ]
        self.pattern: List[frozenset[str]] = pattern
        self.events: Dict[str, Deque[Tuple[float, Set[str]]]] = defaultdict(lambda: deque())
        self.last_emit: Dict[str,float] = {}
        # Metrics
        if not hasattr(self.__class__,'_metrics_init'):
            try:
                if Counter:
                    self.__class__.matches_total = Counter('correlation_temporal_matches_total','Temporal correlation pattern matches')  # type: ignore
                if Gauge:
                    self.__class__.entities_tracked = Gauge('correlation_entities_tracked','Entities tracked for temporal correlation')  # type: ignore
                self.__class__._metrics_init = True
            except Exception:  # pragma: no cover
                pass

    def _entity_key(self, event: dict) -> Optional[str]:
        for k in ('host_id','host','src_host','source_host'):
            v = event.get(k)
            if isinstance(v, str) and v:
                return v.lower()
        return None

    def ingest(self, event: dict, factors: List[str]) -> Tuple[List[str], float]:
        """Ingest an event + its factor list, possibly returning appended correlation factor(s) and delta.

        Returns (new_factors_added, extra_confidence_delta)
        """
        ent = self._entity_key(event)
        if not ent or not factors:
            return [], 0.0
        now = float(event.get('ts') or time.time())
        dq = self.events[ent]
        # Insert
        dq.append((now, set(factors)))
        # Size prune
        while len(dq) > self.max_events_per_entity:
            dq.popleft()
        # Time prune
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        # Metrics
        try:
            if hasattr(self.__class__,'entities_tracked'):
                self.__class__.entities_tracked.set(len(self.events))  # type: ignore
        except Exception:
            pass
        # Pattern match (sequential): only consider sequences that terminate
        # with the current (most recent) event. This avoids matching older
        # completed sequences when the deque accumulates past windows and
        # ensures emission is triggered by the final step.
        if not dq:
            return [], 0.0
        # Require newest event to match final pattern step
        last_ts, last_fset = dq[-1]
        if not last_fset.intersection(self.pattern[-1]):
            return [], 0.0
        # Now search the prior events for the earlier steps in order
        step_idx = 0
        for (ts, fset) in list(dq)[:-1]:
            needed = self.pattern[step_idx]
            if fset.intersection(needed):
                step_idx += 1
                if step_idx >= (len(self.pattern) - 1):
                    # Full match including the current latest event
                    last_emit = self.last_emit.get(ent)
                    if last_emit and (now - last_emit) < self.cooldown_seconds:
                        return [], 0.0
                    self.last_emit[ent] = now
                    try:
                        if hasattr(self.__class__,'matches_total'):
                            self.__class__.matches_total.inc()  # type: ignore
                    except Exception:
                        pass
                    corr_factor = 'corr:multi_stage_lateral_beacon'
                    # Emit only if not already present in the provided factors
                    if corr_factor not in factors:
                        delta = adjust_delta(corr_factor, 0.02)
                        return [corr_factor], delta
                    return [], 0.0
        return [], 0.0

GLOBAL_TEMPORAL_CORRELATOR = TemporalCorrelator()

def record_temporal_correlation(event: dict, factors: List[str]) -> Tuple[List[str], float]:
    try:
        return GLOBAL_TEMPORAL_CORRELATOR.ingest(event, factors)
    except Exception:
        return [], 0.0

__all__ = ['TemporalCorrelator','GLOBAL_TEMPORAL_CORRELATOR','record_temporal_correlation']

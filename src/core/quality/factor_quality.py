"""Factor quality scoring and suppression logic.

Tracks TP/FP counts for factors (approx) and computes suppression decisions based on
configured FP ratio threshold and minimum observation count.
"""
from __future__ import annotations
import os
from typing import Dict, Set, Deque, Tuple
from collections import deque
from collections import defaultdict

try:
    from prometheus_client import Counter, Gauge
except Exception:
    Counter = lambda *a, **k: None  # type: ignore
    Gauge = lambda *a, **k: None    # type: ignore

_factor_tp = Counter('factor_tp_total','True positive factor attributions', ['factor']) if callable(Counter) else None
_factor_fp = Counter('factor_fp_total','False positive factor attributions', ['factor']) if callable(Counter) else None
_suppressed_gauge = Gauge('factor_suppressed','Factor suppression active (1/0)', ['factor']) if callable(Gauge) else None

class FactorQualityManager:
    def __init__(self):
        self.tp: Dict[str,int] = defaultdict(int)
        self.fp: Dict[str,int] = defaultdict(int)
        self.suppressed: Set[str] = set()
        self.fp_ratio_threshold = float(os.getenv('FACTOR_FP_RATIO_THRESHOLD','0.8'))  # suppress if >80% FP
        self.min_observations = int(os.getenv('FACTOR_MIN_OBSERVATIONS','10'))
        # Sliding window (global) last N factor attributions for precision tracking
        self.window_size = int(os.getenv('FACTOR_PRECISION_WINDOW','500'))
        self._window: Deque[Tuple[str,bool]] = deque(maxlen=self.window_size)
        # Aggregate counters for quick precision computation
        self._window_tp = 0
        self._window_fp = 0
        # Lifecycle tracking
        self._suppress_started: Dict[str,float] = {}
        self._suppress_durations: Dict[str,float] = {}  # cumulative if toggled
        self._reactivation_cooldown = float(os.getenv('FACTOR_REENABLE_MIN_SECONDS','3600'))
        self._min_precision_for_reenable = float(os.getenv('FACTOR_REENABLE_MIN_PRECISION','0.6'))

    def record(self, factor: str, is_tp: bool):
        if is_tp:
            self.tp[factor]+=1
            if _factor_tp: _factor_tp.labels(factor=factor).inc()
        else:
            self.fp[factor]+=1
            if _factor_fp: _factor_fp.labels(factor=factor).inc()
        self._evaluate(factor)
        # Maintain sliding window stats
        if len(self._window) == self.window_size:
            # Remove impact of oldest
            old_factor, old_is_tp = self._window[0]
            if old_is_tp:
                self._window_tp -= 1
            else:
                self._window_fp -= 1
        self._window.append((factor, is_tp))
        if is_tp:
            self._window_tp += 1
        else:
            self._window_fp += 1

    def _evaluate(self, factor: str):
        t = self.tp[factor]; f = self.fp[factor]
        total = t+f
        if total < self.min_observations:
            return
        fp_ratio = f / total if total>0 else 0.0
        if fp_ratio >= self.fp_ratio_threshold:
            if factor not in self.suppressed:
                self.suppressed.add(factor)
                if _suppressed_gauge:
                    _suppressed_gauge.labels(factor=factor).set(1)
                # Start lifecycle timer
                if factor not in self._suppress_started:
                    import time as _t
                    self._suppress_started[factor] = _t.time()
        else:
            if factor in self.suppressed:
                self.suppressed.remove(factor)
                if _suppressed_gauge:
                    _suppressed_gauge.labels(factor=factor).set(0)
                # Close lifecycle
                import time as _t
                start = self._suppress_started.pop(factor, None)
                if start:
                    self._suppress_durations[factor] = self._suppress_durations.get(factor,0.0) + (_t.time()-start)

    def filter_factors(self, factors):
        return [f for f in factors if f not in self.suppressed]

    def window_precision(self) -> float:
        total = self._window_tp + self._window_fp
        if total == 0:
            return 0.0
        return self._window_tp / total

    def window_counts(self) -> Dict[str,int]:
        return {
            'tp': self._window_tp,
            'fp': self._window_fp,
            'total': self._window_tp + self._window_fp,
            'window_size': self.window_size
        }

    def suppression_lifecycle(self) -> Dict[str, Dict[str, float | int | str]]:
        """Return lifecycle analytics for suppressed factors.

        Provides: duration (current or cumulative), observations, tp, fp, fp_ratio,
        and re_enable_suggestion (yes/no) based on cooldown + precision recovery.
        """
        import time as _t
        rows: Dict[str, Dict[str, float | int | str]] = {}
        now = _t.time()
        for f in self.suppressed:
            t = self.tp.get(f,0); fp = self.fp.get(f,0); tot = t+fp
            fp_ratio = (fp / tot) if tot else 0.0
            start = self._suppress_started.get(f)
            duration = (now - start) if start else 0.0
            # Re-enable heuristic: enough time elapsed AND precision improved in recent window
            # Approx precision recent: use window counts filtered to factor
            recent_tp = sum(1 for fac,is_tp in self._window if fac==f and is_tp)
            recent_fp = sum(1 for fac,is_tp in self._window if fac==f and not is_tp)
            recent_total = recent_tp + recent_fp
            recent_precision = (recent_tp / recent_total) if recent_total else 0.0
            suggest_reenable = 'no'
            if duration >= self._reactivation_cooldown and recent_total >= max(3, self.min_observations/2):
                if recent_precision >= self._min_precision_for_reenable and fp_ratio < self.fp_ratio_threshold:
                    suggest_reenable = 'yes'
            rows[f] = {
                'tp': t,
                'fp': fp,
                'observations': tot,
                'fp_ratio': round(fp_ratio,3),
                'duration_seconds': round(duration,1),
                'recent_precision': round(recent_precision,3),
                're_enable_suggestion': suggest_reenable
            }
        return rows

_quality_mgr: FactorQualityManager | None = None

def get_quality_manager() -> FactorQualityManager:
    global _quality_mgr
    if _quality_mgr is None:
        _quality_mgr = FactorQualityManager()
    return _quality_mgr

__all__ = ['get_quality_manager','FactorQualityManager']

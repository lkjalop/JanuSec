from __future__ import annotations
import os, time, math, threading, hashlib
from itertools import combinations
from typing import Dict, Tuple, List
from .annotations import emit_edge
from src.core.factors.observe_flags import adjust_delta

class SuppressionCorrelator:
    """Negative correlation module.

    Tracks TP / FP occurrence counts for factor pairs (orderless).
    When FP:TP ratio exceeds threshold with minimum support, emits a suppression factor once per window.
    Suppression reduces (or zeroes) additive correlation deltas downstream (policy kept simple here: emit a factor with small negative delta to subtract).
    """

    def __init__(self):
        self.enabled = os.getenv('SUPPRESSION_ENABLED','1') not in ('0','false','False')
        self.fp_ratio_threshold = float(os.getenv('SUPPRESS_FP_RATIO','3.0') or 3.0)
        self.min_support = int(os.getenv('SUPPRESS_MIN_SUPPORT','6') or 6)
        self.cooldown = int(os.getenv('SUPPRESS_COOLDOWN_SECONDS','900') or 900)
        self.max_pairs = int(os.getenv('SUPPRESS_MAX_PAIRS','30000') or 30000)
        self.window_seconds = int(os.getenv('SUPPRESS_WINDOW_SECONDS','86400') or 86400)
        # pair -> [tp_count, fp_count, last_seen_ts]
        self._stats: Dict[Tuple[str,str], List[float]] = {}
        self._last_emit: Dict[Tuple[str,str], float] = {}
        self._lock = threading.RLock()
        # Metrics (optional)
        try:  # type: ignore
            from prometheus_client import Counter  # type: ignore
            self._emit_counter = Counter('suppression_emitted_total','Total suppression factors emitted', ['reason'])  # type: ignore
        except Exception:  # pragma: no cover
            self._emit_counter = None  # type: ignore

    def _prune(self, now: float):
        cutoff = now - self.window_seconds
        for k, vals in list(self._stats.items()):
            if vals[2] < cutoff:
                self._stats.pop(k, None)
        for k, t in list(self._last_emit.items()):
            if t < cutoff:
                self._last_emit.pop(k, None)

    def ingest(self, event: dict, factors: List[str], had_tp: bool, had_fp: bool) -> Tuple[List[str], float]:
        if not self.enabled or len(factors) < 2:
            return [], 0.0
        now = time.time()
        with self._lock:
            self._prune(now)
            emitted: List[str] = []
            delta_total = 0.0
            uniq = sorted(set(factors))
            # Adaptive low-quality relax thresholds (feedback integration)
            try:
                from src.feedback.store import GLOBAL_FEEDBACK_STORE  # type: ignore
                low_q_thresh = float(os.getenv('FEEDBACK_LOW_QUALITY_THRESH','0.45') or 0.45)
                adaptive_enabled = os.getenv('SUPPRESSION_FEEDBACK_ADAPT','1').lower() not in {'0','false','no'}
            except Exception:
                adaptive_enabled = False
                low_q_thresh = 0.45
            for a,b in combinations(uniq,2):
                key = (a,b)
                if key not in self._stats:
                    if len(self._stats) >= self.max_pairs:
                        continue
                    self._stats[key] = [0.0,0.0,now]  # tp, fp, last
                stats = self._stats[key]
                # Update counts only once per event context
                if had_tp:
                    stats[0] += 1
                if had_fp:
                    stats[1] += 1
                stats[2] = now
                support = stats[0] + stats[1]
                # Two branches: (a) have TP and ratio exceeds threshold; (b) zero TP but FP support large enough
                zero_tp_trigger = (stats[0] == 0 and stats[1] >= self.min_support)
                ratio = (stats[1] / stats[0]) if stats[0] > 0 else float('inf')
                # If both factors low-quality, relax thresholds
                if adaptive_enabled and support < self.min_support:
                    try:
                        tp_a, fp_a, qa = GLOBAL_FEEDBACK_STORE.get_factor_quality(a)
                        tp_b, fp_b, qb = GLOBAL_FEEDBACK_STORE.get_factor_quality(b)
                        if qa < low_q_thresh and qb < low_q_thresh:
                            # reduce required support & ratio threshold temporarily
                            eff_min_support = max(2, int(self.min_support * 0.5))
                            eff_ratio_threshold = max(1.5, self.fp_ratio_threshold * 0.7)
                        else:
                            eff_min_support = self.min_support
                            eff_ratio_threshold = self.fp_ratio_threshold
                    except Exception:
                        eff_min_support = self.min_support
                        eff_ratio_threshold = self.fp_ratio_threshold
                else:
                    eff_min_support = self.min_support
                    eff_ratio_threshold = self.fp_ratio_threshold
                if support < eff_min_support:
                    continue
                if zero_tp_trigger or ratio >= eff_ratio_threshold:
                    last = self._last_emit.get(key)
                    if last and (now - last) < self.cooldown:
                        continue
                    self._last_emit[key] = now
                    # stable small hash to differentiate suppression pairs if needed
                    h = hashlib.sha1(f"{a}|{b}".encode('utf-8')).hexdigest()[:6]
                    suppress_factor = f'corr:suppress_low_value'
                    if suppress_factor not in emitted and suppress_factor not in factors:
                        emitted.append(suppress_factor)
                        # Negative delta (bounded)
                        delta = -abs(adjust_delta('corr:suppress_low_value', 0.01))
                        delta_total += delta
                        try:
                            if self._emit_counter:
                                reason = 'zero_tp' if zero_tp_trigger else 'ratio'
                                self._emit_counter.labels(reason=reason).inc()  # type: ignore
                        except Exception:
                            pass
                        emit_edge({
                            'edge_type': 'suppression',
                            'rule_id': 'fp_ratio_pair',
                            'ts': now,
                            'entities': [event.get('incident_id') or event.get('host') or ''],
                            'input_factors': [a,b],
                            'output_factor': suppress_factor,
                            'delta': delta,
                            'meta': {
                                'fp': stats[1],
                                'tp': stats[0],
                                'ratio': ratio,
                                'support': support,
                                'hash': h
                            }
                        })
            return emitted, delta_total

GLOBAL_SUPPRESSION_CORRELATOR = SuppressionCorrelator()

def record_suppression_correlation(event: dict, factors: List[str], had_tp: bool, had_fp: bool):
    try:
        return GLOBAL_SUPPRESSION_CORRELATOR.ingest(event, factors, had_tp, had_fp)
    except Exception:
        return [], 0.0

__all__ = ['SuppressionCorrelator','GLOBAL_SUPPRESSION_CORRELATOR','record_suppression_correlation']
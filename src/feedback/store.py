from __future__ import annotations
import time, threading, math, hashlib
from typing import Dict, Any, Optional, List, Tuple

_QUALITY_ALPHA = 1.0  # Laplace smoothing constant (can be tuned later)
_MAX_FACTORS_SNAPSHOT = 150  # hard cap to bound record size

class FeedbackStore:
    """In-memory feedback store with factor-level TP/FP accounting and quality scoring.

    Structure per event_id:
        {
          'event_id': str,
          'classification': str,  # tp|fp|malicious|benign
          'decision': {'confidence': float|None, 'verdict': str|None, 'type': str|None},
          'factors': [ {'name': str, 'delta': float|None, 'weight': float|None} ],
          'comment': str|None,
          'ts': float (epoch seconds)
        }
    Factor quality stats accumulate across all feedback submissions (not per-event).
    """
    def __init__(self):
        self._lock = threading.RLock()
        self._events: Dict[str, Dict[str,Any]] = {}
        # factor -> {'tp': int, 'fp': int}
        self._factor_counts: Dict[str, Dict[str,int]] = {}
        self._last_recompute: float | None = None
        self._quality_cache: Dict[str, float] = {}

    # ---------------- Internal helpers ----------------
    def _normalize_classification(self, verdict: str) -> str:
        v = verdict.lower()
        # map synonyms
        if v in {'tp','true_positive','malicious','mal'}:
            return 'tp'
        if v in {'fp','false_positive','benign','clean'}:
            return 'fp'
        return v  # allow future labels (noise, etc.)

    def _update_factor_counts(self, classification: str, factors: List[Dict[str,Any]]):
        is_tp = classification == 'tp'
        is_fp = classification == 'fp'
        if not (is_tp or is_fp):
            return  # only track for tp/fp labels initially
        for f in factors[:_MAX_FACTORS_SNAPSHOT]:
            name = f.get('name')
            if not name:
                continue
            entry = self._factor_counts.setdefault(name, {'tp':0,'fp':0})
            if is_tp:
                entry['tp'] += 1
            elif is_fp:
                entry['fp'] += 1

    # ---------------- Public API ----------------
    def upsert(self, event_id: str, verdict: str, factors: List[Dict[str,Any]], decision_meta: Optional[Dict[str,Any]] = None, comment: Optional[str]=None) -> Dict[str,Any]:
        cls = self._normalize_classification(verdict)
        rec: Dict[str,Any] = {
            'event_id': event_id,
            'classification': cls,
            'decision': {
                'confidence': (decision_meta or {}).get('confidence'),
                'verdict': (decision_meta or {}).get('verdict'),
                'type': (decision_meta or {}).get('decision_type') or (decision_meta or {}).get('type')
            },
            'factors': factors[:_MAX_FACTORS_SNAPSHOT],
            'comment': comment,
            'ts': time.time(),
        }
        with self._lock:
            self._events[event_id] = rec  # immutable snapshot replace
            self._update_factor_counts(cls, rec['factors'])
        return rec

    def get(self, event_id: str) -> Optional[Dict[str,Any]]:
        with self._lock:
            return self._events.get(event_id)

    def stats(self) -> Dict[str,Any]:
        with self._lock:
            counts: Dict[str,int] = {}
            for r in self._events.values():
                v = r['classification']
                counts[v] = counts.get(v,0)+1
            return {'total_events': len(self._events), 'by_classification': counts}

    # ---------------- Factor quality ----------------
    def _laplace_precision(self, tp: int, fp: int, alpha: float = _QUALITY_ALPHA) -> float:
        return (tp + alpha) / (tp + fp + 2*alpha)

    def recompute_quality(self) -> None:
        with self._lock:
            self._quality_cache = {}
            for name, c in self._factor_counts.items():
                self._quality_cache[name] = self._laplace_precision(c['tp'], c['fp'])
            self._last_recompute = time.time()

    def quality_metadata(self) -> Dict[str, Any]:
        with self._lock:
            total_factors = len(self._factor_counts)
            total_votes = sum(c['tp'] + c['fp'] for c in self._factor_counts.values())
            return {
                'last_recompute': self._last_recompute,
                'factor_count': total_factors,
                'total_votes': total_votes,
            }

    def get_factor_quality(self, factor: str) -> Tuple[int,int,float]:
        with self._lock:
            c = self._factor_counts.get(factor, {'tp':0,'fp':0})
            score = self._quality_cache.get(factor)
            if score is None:
                score = self._laplace_precision(c['tp'], c['fp'])
            return c['tp'], c['fp'], score

    def list_factor_qualities(self, limit: int = 500, sort: str = 'asc') -> List[Dict[str,Any]]:
        with self._lock:
            # ensure cache
            if not self._quality_cache:
                for name, c in self._factor_counts.items():
                    self._quality_cache[name] = self._laplace_precision(c['tp'], c['fp'])
            rows = [
                {'factor': n, 'tp': c['tp'], 'fp': c['fp'], 'score': self._quality_cache.get(n, 0.5)}
                for n, c in self._factor_counts.items()
            ]
            reverse = (sort == 'desc')
            rows.sort(key=lambda r: r['score'], reverse=reverse)
            return rows[:limit]

GLOBAL_FEEDBACK_STORE = FeedbackStore()

__all__ = ['GLOBAL_FEEDBACK_STORE','FeedbackStore']

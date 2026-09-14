import math
import time
from typing import List, Dict, Any, Tuple
from src.repositories.feature_store_repo import FeatureStoreRepo
from src.repositories.precision_metrics_repo import PrecisionMetricsRepo
from src.repositories.llm_claims_repo import list_unadjudicated, stats as claim_stats, init_db as claims_init_db
from src.repositories.llm_claims_repo import _get_conn as _claims_conn  # type: ignore


def _binomial_confidence_interval(k: int, n: int, alpha: float = 0.05) -> Tuple[float, float]:
    # Wilson score interval
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    z = 1.959963984540054  # 95%
    den = 1 + z*z/n
    centre = p + z*z/(2*n)
    adj = z * math.sqrt((p*(1-p)/n) + z*z/(4*n*n))
    lo = (centre - adj)/den
    hi = (centre + adj)/den
    return (max(0.0, lo), min(1.0, hi))


class ReplayEvaluator:
    def __init__(self, db_path: str | None = None):
        self.feature_store = FeatureStoreRepo(db_path=db_path)
        self.precision_repo = PrecisionMetricsRepo()
        try:
            from src.core.metrics import make_counter
            self._replay_counter = make_counter('replay_runs_total', 'Total replay evaluations run')
        except Exception:
            self._replay_counter = None

    def replay(self, weights: Dict[str, float], sample_limit: int = 2000) -> Dict[str, Any]:
        """Replay recent stored events deterministically and compute TP/FP estimates.

        Returns report with counts and confidence intervals.
        """
        events = self.feature_store.list_recent(limit=sample_limit)
        # FeatureStoreRepo.list_recent may be async or sync; handle both
        if hasattr(events, '__await__'):
            import asyncio
            events = asyncio.get_event_loop().run_until_complete(events)

        baseline_hits = 0
        proposed_hits = 0
        # assume baseline uses uniform weight 1 for known features
        for e in events:
            ev = e.get('event') or {}
            feats = ev.get('features') or {}
            base_score = sum(1.0 for _ in feats.keys())
            prop_score = 0.0
            for k, v in weights.items():
                try:
                    if feats.get(k):
                        prop_score += float(v) * (1.0 if feats.get(k) else 0.0)
                except Exception:
                    pass
            if base_score >= 1.0:
                baseline_hits += 1
            if prop_score >= 1.0:
                proposed_hits += 1

        # Estimate TP/FP using historical precision prior and incorporate human adjudications where available
        hist_prior = 0.1
        try:
            # try extract rule id from weights container if present
            # not guaranteed; fallback to default
            hist = self.precision_repo.fp_reduction_trend(int(time.time()) - 86400*30, int(time.time()))
            if hist:
                last = hist[-1]
                hist_prior = last.get('precision') or hist_prior
        except Exception:
            pass

        # Incorporate adjudicated claims as stronger priors when available
        try:
            claims_init_db()
            conn = _claims_conn()
            cur = conn.cursor()
            # Aggregate adjudicated claim stats to adjust precision estimate
            r = cur.execute("SELECT COUNT(1) as c, SUM(is_correct) as correct FROM claims WHERE adjudicated=1").fetchone()
            if r and r['c'] and r['c'] > 0:
                adjud_count = int(r['c'])
                correct = int(r['correct'] or 0)
                adj_prec = correct / adjud_count
                # blend hist_prior with adjudicated precision (simple average)
                hist_prior = (hist_prior + adj_prec) / 2.0
            conn.close()
        except Exception:
            pass

        baseline_tp = int(round(baseline_hits * hist_prior))
        baseline_fp = baseline_hits - baseline_tp
        proposed_tp = int(round(proposed_hits * hist_prior))
        proposed_fp = proposed_hits - proposed_tp

        # compute precision and CI
        baseline_prec = (baseline_tp / baseline_hits) if baseline_hits else None
        proposed_prec = (proposed_tp / proposed_hits) if proposed_hits else None
        baseline_ci = _binomial_confidence_interval(baseline_tp, baseline_hits) if baseline_hits else (0.0, 1.0)
        proposed_ci = _binomial_confidence_interval(proposed_tp, proposed_hits) if proposed_hits else (0.0, 1.0)

        try:
            if getattr(self, '_replay_counter', None) is not None:
                self._replay_counter.inc()
        except Exception:
            pass

        return {
            'baseline_hits': baseline_hits,
            'proposed_hits': proposed_hits,
            'baseline_tp': baseline_tp,
            'baseline_fp': baseline_fp,
            'proposed_tp': proposed_tp,
            'proposed_fp': proposed_fp,
            'baseline_precision': baseline_prec,
            'proposed_precision': proposed_prec,
            'baseline_ci': baseline_ci,
            'proposed_ci': proposed_ci,
            'sample_size': len(events),
            'timestamp': int(time.time()),
        }

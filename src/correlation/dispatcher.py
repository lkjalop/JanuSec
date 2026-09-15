from __future__ import annotations
from typing import List, Tuple

import time, os
from .temporal import record_temporal_correlation
from .cooccurrence import record_cooccurrence_correlation
from .campaigns import record_campaign_correlation
from .suppression import record_suppression_correlation
from .sequences import record_sequence_correlation
from src.metrics.correlation_impact import record_correlation_impact

_BUDGET_MS = float(os.getenv('CORR_TIME_BUDGET_MS','0') or 0)  # 0 means disabled
_OPTIONAL_MODULES = {
    'cooccurrence': True,
    'campaign': True,
    'suppression': True,
    'sequence': True,
}
_SKIP_ON_BUDGET = set(os.getenv('CORR_SKIP_ORDER','sequence,hashed_pmi').split(','))  # planned future modules

def correlate(event: dict, factors: List[str], *, had_tp: bool = False, had_fp: bool = False) -> Tuple[List[str], float]:
    """Run all correlation modules; return (new_factors, added_delta).

    had_tp / had_fp indicate whether the pre-correlation context already contained
    labeled true-positive or false-positive factors. This enables lift metrics.
    """
    new_total: List[str] = []
    delta_total = 0.0
    start_all = time.time()
    # Temporal correlation (always-on)
    nf_t, d_t = record_temporal_correlation(event, factors)
    if nf_t:
        new_total.extend(nf_t)
        delta_total += d_t
        # Extend factors with new ones for downstream correlation modules (so co-occurrence can see them)
        factors = factors + nf_t
    # Co-occurrence correlation (optional for budget)
    if _OPTIONAL_MODULES.get('cooccurrence', True):
        if _BUDGET_MS > 0 and (time.time()-start_all)*1000.0 > _BUDGET_MS and 'cooccurrence' in _SKIP_ON_BUDGET:
            _OPTIONAL_MODULES['cooccurrence'] = False
        if _OPTIONAL_MODULES.get('cooccurrence'):
            nf_c, d_c = record_cooccurrence_correlation(event, factors)
            if nf_c:
                new_total.extend(nf_c)
                delta_total += d_c
                factors = factors + nf_c
            if _BUDGET_MS > 0:
                elapsed_ms = (time.time() - start_all)*1000.0
                if elapsed_ms > _BUDGET_MS and 'cooccurrence' in _SKIP_ON_BUDGET:
                    _OPTIONAL_MODULES['cooccurrence'] = False  # adaptively disable
    # Campaign correlation
    if _OPTIONAL_MODULES.get('campaign', True):
        if _BUDGET_MS > 0 and (time.time()-start_all)*1000.0 > _BUDGET_MS and 'campaign' in _SKIP_ON_BUDGET:
            _OPTIONAL_MODULES['campaign'] = False
        if _OPTIONAL_MODULES.get('campaign'):
            nf_cam, d_cam = record_campaign_correlation(event, factors)
            if nf_cam:
                new_total.extend(nf_cam)
                delta_total += d_cam
                factors = factors + nf_cam
            if _BUDGET_MS > 0:
                elapsed_ms = (time.time() - start_all)*1000.0
                if elapsed_ms > _BUDGET_MS and 'campaign' in _SKIP_ON_BUDGET:
                    _OPTIONAL_MODULES['campaign'] = False
    # Suppression
    if _OPTIONAL_MODULES.get('suppression', True):
        if _BUDGET_MS > 0 and (time.time()-start_all)*1000.0 > _BUDGET_MS and 'suppression' in _SKIP_ON_BUDGET:
            _OPTIONAL_MODULES['suppression'] = False
        if _OPTIONAL_MODULES.get('suppression'):
            nf_sup, d_sup = record_suppression_correlation(event, factors, had_tp=had_tp, had_fp=had_fp)
            if nf_sup:
                new_total.extend(nf_sup)
                delta_total += d_sup
            if _BUDGET_MS > 0:
                elapsed_ms = (time.time() - start_all)*1000.0
                if elapsed_ms > _BUDGET_MS and 'suppression' in _SKIP_ON_BUDGET:
                    _OPTIONAL_MODULES['suppression'] = False
    # Sequence correlation
    if _OPTIONAL_MODULES.get('sequence', True):
        if _BUDGET_MS > 0 and (time.time()-start_all)*1000.0 > _BUDGET_MS and 'sequence' in _SKIP_ON_BUDGET:
            _OPTIONAL_MODULES['sequence'] = False
        if _OPTIONAL_MODULES.get('sequence'):
            nf_seq, d_seq = record_sequence_correlation(event, factors)
            if nf_seq:
                new_total.extend(nf_seq)
                delta_total += d_seq
                factors = factors + nf_seq
            if _BUDGET_MS > 0:
                elapsed_ms = (time.time() - start_all)*1000.0
                if elapsed_ms > _BUDGET_MS and 'sequence' in _SKIP_ON_BUDGET:
                    _OPTIONAL_MODULES['sequence'] = False
    # Record impact metrics (best-effort)
    try:
        record_correlation_impact(new_total, had_tp=had_tp, had_fp=had_fp)
    except Exception:
        pass
    # Optional dynamic scaling of aggregate delta based on average factor quality
    if os.getenv('FEATURE_DYNAMIC_FACTOR_SCALING','0').lower() in {'1','true','yes'} and new_total:
        try:
            from src.feedback.store import GLOBAL_FEEDBACK_STORE  # type: ignore
            qualities = []
            for f in new_total:
                _tp,_fp,q = GLOBAL_FEEDBACK_STORE.get_factor_quality(f)
                qualities.append(q)
            if qualities:
                avg_q = sum(qualities)/len(qualities)
                # scale between 0.85 .. 1.15 (linear around 0.5 center)
                scale = 0.85 + 0.3 * avg_q
                scale = max(0.7, min(1.25, scale))
                delta_total *= scale
        except Exception:
            pass
    return new_total, delta_total

__all__ = ['correlate']

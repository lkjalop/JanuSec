from __future__ import annotations

"""Correlation impact metrics (true-positive / false-positive context counters).

These counters allow measuring whether correlation emissions occur in contexts
that already have labeled TP or FP baseline factors, enabling downstream lift
analysis (TP lift vs FP amplification).

Usage:
    from metrics.correlation_impact import record_correlation_impact
    record_correlation_impact(new_factors, had_tp=True, had_fp=False)

Counters (created lazily, no-op if prometheus_client missing):
 - correlation_factors_emitted_total
 - correlation_tp_context_total  (emitted while event had ≥1 TP factor pre-correlation)
 - correlation_fp_context_total  (emitted while event had ≥1 FP factor pre-correlation)
 - correlation_tp_only_total     (TP context and not FP)
 - correlation_fp_only_total     (FP context and not TP)
 - correlation_neutral_context_total (no TP/FP context)
"""

try:  # pragma: no cover
    from prometheus_client import Counter  # type: ignore
except Exception:  # pragma: no cover
    Counter = None  # type: ignore

_INIT = False
correlation_factors_emitted_total = None
correlation_tp_context_total = None
correlation_fp_context_total = None
correlation_tp_only_total = None
correlation_fp_only_total = None
correlation_neutral_context_total = None

def _init():  # pragma: no cover - trivial
    global _INIT
    if _INIT or Counter is None:
        return
    try:
        global correlation_factors_emitted_total, correlation_tp_context_total, correlation_fp_context_total
        global correlation_tp_only_total, correlation_fp_only_total, correlation_neutral_context_total
        correlation_factors_emitted_total = Counter('correlation_factors_emitted_total','Correlation factors emitted (all mechanisms)')  # type: ignore
        correlation_tp_context_total = Counter('correlation_tp_context_total','Correlation emissions in TP context (event already had TP factors)')  # type: ignore
        correlation_fp_context_total = Counter('correlation_fp_context_total','Correlation emissions in FP context (event already had FP factors)')  # type: ignore
        correlation_tp_only_total = Counter('correlation_tp_only_context_total','Correlation emissions where TP context and NOT FP context')  # type: ignore
        correlation_fp_only_total = Counter('correlation_fp_only_context_total','Correlation emissions where FP context and NOT TP context')  # type: ignore
        correlation_neutral_context_total = Counter('correlation_neutral_context_total','Correlation emissions with no TP/FP context')  # type: ignore
        _INIT = True
    except Exception:
        pass

def record_correlation_impact(new_factors, had_tp: bool, had_fp: bool):
    if not new_factors:
        return
    _init()
    try:
        if correlation_factors_emitted_total:
            for _ in new_factors:
                correlation_factors_emitted_total.inc()
        if had_tp and correlation_tp_context_total:
            correlation_tp_context_total.inc()
        if had_fp and correlation_fp_context_total:
            correlation_fp_context_total.inc()
        if had_tp and not had_fp and correlation_tp_only_total:
            correlation_tp_only_total.inc()
        if had_fp and not had_tp and correlation_fp_only_total:
            correlation_fp_only_total.inc()
        if (not had_tp and not had_fp) and correlation_neutral_context_total:
            correlation_neutral_context_total.inc()
    except Exception:
        pass

__all__ = ['record_correlation_impact']

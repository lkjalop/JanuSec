from __future__ import annotations

import math
from typing import Dict, Any, List
import os
from fastapi import APIRouter, HTTPException, Query, Request

try:
    from src.eval.ab_analysis import uplift_and_pvalue, beta_interval, sample_size_for_uplift
except Exception:
    # Lightweight fallbacks when SciPy is unavailable
    def uplift_and_pvalue(control_tp: int, control_total: int, treat_tp: int, treat_total: int) -> Dict[str, float]:
        pc = (control_tp / control_total) if control_total > 0 else 0.0
        pt = (treat_tp / treat_total) if treat_total > 0 else 0.0
        uplift = pt - pc
        # Wald z-test approximation
        pooled = (control_tp + treat_tp) / float((control_total + treat_total) or 1)
        var = pooled * (1 - pooled)
        se = math.sqrt(var * (1.0 / (control_total or 1) + 1.0 / (treat_total or 1)))
        z = (pt - pc) / se if se and math.isfinite(se) and se > 0 else 0.0
        # two-tailed p-value using error function
        p = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(z) / math.sqrt(2.0))))
        return {"control_prop": pc, "treat_prop": pt, "uplift": uplift, "p_value": float(p)}

    def beta_interval(k: int, n: int, alpha: float = 0.05):
        # Normal approximation fallback: p ± z * sqrt(p*(1-p)/n)
        if n <= 0:
            return 0.0, 1.0
        p = k / n
        z = 1.96 if abs(alpha - 0.05) < 1e-9 else 1.96  # simple default
        se = math.sqrt((p * (1 - p)) / n)
        lo = max(0.0, p - z * se)
        hi = min(1.0, p + z * se)
        return float(lo), float(hi)

    def sample_size_for_uplift(baseline_prop: float, min_detectable_uplift: float, alpha: float = 0.05, power: float = 0.8) -> int:
        if min_detectable_uplift == 0:
            return 0
        p1 = baseline_prop
        p2 = baseline_prop + min_detectable_uplift
        # z-scores (approx)
        z_alpha = 1.96
        z_beta = 0.84
        sd = math.sqrt(p1 * (1 - p1) + p2 * (1 - p2))
        n = ((z_alpha + z_beta) * sd / min_detectable_uplift) ** 2
        return int(math.ceil(n))

from src.repositories.precision_metrics_repo import PrecisionMetricsRepo
from .tenant_helpers import resolve_tenant_id

router = APIRouter(prefix="/api/v1/metrics", tags=["ab-analysis"])


@router.get("/ab/analysis")
def ab_analysis(
    request: Request,
    tenant_id: str = Query(...),
    test_id: str = Query(...),
    alpha: float = Query(0.05),
    mde: float = Query(0.03),
) -> Dict[str, Any]:
    """Return AB comparative analysis for the top two variants by precision.

    Computes uplift, p-value (two-proportion test), and per-variant credible intervals.
    """
    try:
        repo = PrecisionMetricsRepo(db_path=os.getenv("JANUSEC_SQLITE_PATH", "data/janusec.db"))
    except Exception:
        repo = PrecisionMetricsRepo("data/janusec.db")

    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
        variants: List[Dict[str, Any]] = repo.get_ab_test_summary(tenant_id, test_id)
    except Exception as e:
        # If the lightweight repo fails, surface a safe error
        raise HTTPException(status_code=500, detail=str(e))

    stats: List[Dict[str, Any]] = []
    for v in variants:
        tp = int(v.get("tp") or 0)
        fp = int(v.get("fp") or 0)
        fn = int(v.get("fn") or 0)
        n = tp + fp
        precision = (tp / n) if n > 0 else None
        lo, hi = beta_interval(tp, n, alpha=alpha) if n > 0 else (None, None)
        stats.append({
            "variant": v.get("variant") or "base",
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "n": n,
            "precision": precision,
            "ci": {"lo": lo, "hi": hi},
        })

    active = [s for s in stats if s["n"] > 0 and s["precision"] is not None]
    if len(active) < 2:
        return {"tenant_id": tenant_id, "test_id": test_id, "stats": stats, "comparison": None, "reason": "insufficient_variants"}

    active.sort(key=lambda x: (x["precision"] or 0.0), reverse=True)
    a, b = active[0], active[1]
    comp = uplift_and_pvalue(b["tp"], b["n"], a["tp"], a["n"])
    # include sample-size guidance for configured MDE
    try:
        baseline = b["precision"] or 0.0
        needed_n = sample_size_for_uplift(baseline, mde, alpha=alpha, power=0.8)
    except Exception:
        needed_n = None

    return {
        "tenant_id": tenant_id,
        "test_id": test_id,
        "stats": stats,
        "comparison": {
            "a": a["variant"],
            "b": b["variant"],
            "uplift": comp["uplift"],
            "p_value": comp["p_value"],
            "control_prop": comp["control_prop"],
            "treat_prop": comp["treat_prop"],
            "mde": mde,
            "required_sample_per_group": needed_n,
        },
    }

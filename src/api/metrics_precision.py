from fastapi import APIRouter, HTTPException, Query
from typing import Optional, Dict, Any, List
import os
import math
from ..repositories.precision_metrics_repo import get_daily_trend, get_rule_precision, PrecisionMetricsRepo
try:
    from src.eval.ab_analysis import uplift_and_pvalue, beta_interval, sample_size_for_uplift  # type: ignore
except Exception:
    # Lightweight fallbacks if SciPy not present
    def uplift_and_pvalue(control_tp: int, control_total: int, treat_tp: int, treat_total: int) -> Dict[str, float]:
        pc = (control_tp / control_total) if control_total > 0 else 0.0
        pt = (treat_tp / treat_total) if treat_total > 0 else 0.0
        uplift = pt - pc
        pooled = (control_tp + treat_tp) / float((control_total + treat_total) or 1)
        var = pooled * (1 - pooled)
        se = math.sqrt(var * (1.0 / (control_total or 1) + 1.0 / (treat_total or 1)))
        z = (pt - pc) / se if se and math.isfinite(se) and se > 0 else 0.0
        p = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(z) / math.sqrt(2.0))))
        return {"control_prop": pc, "treat_prop": pt, "uplift": uplift, "p_value": float(p)}

    def beta_interval(k: int, n: int, alpha: float = 0.05):
        if n <= 0:
            return 0.0, 1.0
        p = k / n
        z = 1.96
        se = math.sqrt((p * (1 - p)) / n)
        lo = max(0.0, p - z * se)
        hi = min(1.0, p + z * se)
        return float(lo), float(hi)

    def sample_size_for_uplift(baseline_prop: float, min_detectable_uplift: float, alpha: float = 0.05, power: float = 0.8) -> int:
        if min_detectable_uplift == 0:
            return 0
        p1 = baseline_prop
        p2 = baseline_prop + min_detectable_uplift
        z_alpha = 1.96
        z_beta = 0.84
        sd = math.sqrt(p1 * (1 - p1) + p2 * (1 - p2))
        n = ((z_alpha + z_beta) * sd / min_detectable_uplift) ** 2
        return int(math.ceil(n))

router = APIRouter(prefix="/api/v1/metrics")


@router.get("/fp_reduction_trend")
def fp_reduction_trend(days: Optional[int] = 30):
    try:
        return get_daily_trend(days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rule_precision/{rule_id}")
def rule_precision(rule_id: str, days: Optional[int] = 30):
    try:
        return get_rule_precision(rule_id, days)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ab/analysis")
def ab_analysis(
    tenant_id: str = Query(...),
    test_id: str = Query(...),
    alpha: float = Query(0.05),
    mde: float = Query(0.03),
) -> Dict[str, Any]:
    """AB comparative analysis for top two variants by precision.

    Wired into a core metrics router to ensure availability in tests.
    """
    try:
        repo = PrecisionMetricsRepo(db_path=os.getenv("JANUSEC_SQLITE_PATH", "data/janusec.db"))
        variants: List[Dict[str, Any]] = repo.get_ab_test_summary(tenant_id, test_id)
    except Exception as e:
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


@router.get('/daily_precision')
def daily_precision(
    start_ts: int = Query(..., description='UTC start timestamp (00:00 boundary recommended)'),
    end_ts: int = Query(..., description='UTC end timestamp (exclusive)'),
    rule_id: Optional[str] = Query(None),
    ab_variant: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Aggregated daily TP/FP counts and precision from optional precision_daily table.

    Provided here to ensure route availability even if optional router import fails.
    """
    try:
        db_path = os.getenv('JANUSEC_SQLITE_PATH', 'data/janusec.db')
        import sqlite3
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        params: List[Any] = []
        where = ['day >= ?', 'day < ?']
        params.extend([start_ts, end_ts])
        if rule_id:
            where.append('rule_id = ?')
            params.append(rule_id)
        if ab_variant:
            where.append('ab_variant = ?')
            params.append(ab_variant)
        sql = 'SELECT day, rule_id, ab_variant, tp, fp FROM precision_daily WHERE ' + ' AND '.join(where) + ' ORDER BY day ASC'
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        conn.close()
        series: List[Dict[str, Any]] = []
        for r in rows:
            tp = int(r['tp'] or 0)
            fp = int(r['fp'] or 0)
            total = tp + fp
            series.append({
                'day_ts': int(r['day']),
                'rule_id': r['rule_id'],
                'ab_variant': r['ab_variant'] or 'control',
                'tp': tp,
                'fp': fp,
                'total': total,
                'precision': (tp / total) if total > 0 else None,
            })
        return {'start_ts': start_ts, 'end_ts': end_ts, 'series': series}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

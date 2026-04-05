from __future__ import annotations
from fastapi import APIRouter, Request, HTTPException
from datetime import datetime, date
from typing import Any, List
from src.api.tenant_helpers import resolve_tenant_id

router = APIRouter(prefix='/api/v1/dashboard', tags=['Dashboard'])


@router.get('/fp_reduction')
async def fp_reduction(request: Request, tenant_id: str | None = None, test_id: str | None = None, start: str | None = None, end: str | None = None) -> Any:
    """Return FP/TP time-series and AB variant breakdown for selected test.

    - tenant_id: optional; if omitted, return global aggregation
    - test_id: optional; include AB variant summary when provided
    - start/end: ISO date strings (YYYY-MM-DD). Defaults to last 14 days.
    """
    try:
        from src.repositories.precision_metrics_repo import PrecisionMetricsRepo
        from src.repositories import decision_labels_repo
    except Exception:
        raise HTTPException(status_code=500, detail='repos_unavailable')

    try:
        db = PrecisionMetricsRepo('data/precision_metrics.db')
    except Exception:
        raise HTTPException(status_code=500, detail='precision_db_error')

    # date range defaults
    try:
        if start:
            start_d = datetime.fromisoformat(start).date()
        else:
            start_d = date.today()
        if end:
            end_d = datetime.fromisoformat(end).date()
        else:
            end_d = start_d
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_date')

    tenant_id = resolve_tenant_id(request, tenant_id)
    # Query daily precision rows
    rows = db.get_daily_metrics(tenant_id or '', start_d, end_d)

    # If test_id provided, get AB variant summary
    ab_summary: List[dict] = []
    if test_id:
        try:
            ab_rows = await decision_labels_repo.ab_test_daily(tenant_id, test_id, start_d.isoformat(), (end_d + __import__('datetime').timedelta(days=1)).isoformat())
            # Convert to time-series per variant
            summary = {}
            for r in ab_rows:
                d = r.get('day')
                var = r.get('variant')
                entry = summary.setdefault(var, [])
                entry.append({'day': d.isoformat() if isinstance(d, (date, datetime)) else d, 'tp': r.get('tp', 0), 'fp': r.get('fp', 0), 'fn': r.get('fn', 0)})
            ab_summary = [{'variant': k, 'rows': v} for k, v in summary.items()]
        except Exception:
            ab_summary = []

    return {'ok': True, 'tenant_id': tenant_id, 'start': start_d.isoformat(), 'end': end_d.isoformat(), 'daily': rows, 'ab': ab_summary}

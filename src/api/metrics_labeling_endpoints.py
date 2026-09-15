from __future__ import annotations
from fastapi import APIRouter, Request, HTTPException
from typing import Any
from datetime import datetime, timedelta
from src.api.tenant_helpers import resolve_tenant_id

router = APIRouter(prefix='/api/v1/metrics', tags=['Metrics'])


@router.get('/labeling', summary='Return per-factor and per-decision labeling aggregates')
async def labeling_metrics(tenant_id: str | None = None, start: str | None = None, end: str | None = None, request: Request = None) -> dict[str, Any]:
    """Return a simple aggregate from `decision_labels`.

    Query params: tenant_id, start (ISO date), end (ISO date). Returns TP/FP/FN
    per day and per-factor counts aggregated from the labels table. This is
    lightweight and intended for dashboards / pilot experiments.
    """
    try:
        from src.repositories import decision_labels_repo
    except Exception:
        raise HTTPException(status_code=500, detail='labels repo unavailable')

    # Default to last 7 days
    if not end:
        end_dt = datetime.utcnow()
    else:
        end_dt = datetime.fromisoformat(end)
    if not start:
        start_dt = end_dt - timedelta(days=7)
    else:
        start_dt = datetime.fromisoformat(start)

    # Use repo aggregator for daily counts (graceful when DB disabled in tests)
    tenant_id = resolve_tenant_id(request, tenant_id)
    try:
        rows = await decision_labels_repo.aggregate_daily(tenant_id, start_dt.isoformat(), end_dt.isoformat())
    except Exception as e:
        try:
            from src.db.database import DatabaseNotAvailable
            if isinstance(e, DatabaseNotAvailable):
                rows = []
            else:
                raise
        except Exception:
            # If any import or unexpected error, fall back to empty rows
            rows = []

    # Build a minimal factor-level summary by scanning recent labels (best-effort)
    try:
        from src.db.database import fetch
        FACTOR_SQL = """
        SELECT label, COUNT(*) as cnt
        FROM decision_labels
        WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz
        GROUP BY label
        """
        # best-effort: run raw fetch if available
        factor_rows = await fetch(FACTOR_SQL, start_dt.isoformat(), end_dt.isoformat())
        factor_summary = {r['label']: int(r['cnt']) for r in factor_rows}
    except Exception:
        factor_summary = {}

    return {'ok': True, 'daily': rows, 'factor_summary': factor_summary, 'start': start_dt.isoformat(), 'end': end_dt.isoformat()}

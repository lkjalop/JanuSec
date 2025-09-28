from __future__ import annotations

from fastapi import APIRouter, Depends

from ..dependencies import get_platform_state
from ..state import PlatformState

router = APIRouter()


@router.get('/api/v1/metrics/executive')
def metrics_exec(state: PlatformState = Depends(get_platform_state)) -> dict:
    return state.aggregate_metrics()


@router.get('/api/v1/tenant/{tenant_id}/metrics/executive')
def tenant_metrics_exec(tenant_id: str, state: PlatformState = Depends(get_platform_state)) -> dict:
    return state.tenant_metrics(tenant_id)


@router.get('/api/v1/metrics/summary')
def metrics_summary(state: PlatformState = Depends(get_platform_state)) -> dict:
    agg = state.aggregate_metrics()
    alerts = [snapshot.model_dump() for snapshot in state.recent_alerts(limit=25)]
    return {
        'decision_counts': agg.get('decisions', {}),
        'heavy_ops': agg.get('heavy_ops'),
        'realized_cost': agg.get('realized_cost'),
        'recent_alerts': alerts,
    }

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
    # Return per-tenant decision counts normalized to include dedupe and upserts keys
    decisions = agg.get('decisions', {}) or {}
    out: dict[str, dict] = {}
    for tenant, counts in decisions.items():
        if not isinstance(counts, dict):
            continue
        # Map legacy allow/deny/quarantine into dedupe if present
        dedupe = int(counts.get('dedupe', 0) or 0)
        if dedupe == 0:
            dedupe = int(counts.get('allow', 0) or 0) + int(counts.get('deny', 0) or 0) + int(counts.get('quarantine', 0) or 0)
        out[tenant] = {
            'dedupe': dedupe,
            'upserts_success': int(counts.get('upserts_success', 0) or 0),
            'upserts_failed': int(counts.get('upserts_failed', 0) or 0)
        }
    return out

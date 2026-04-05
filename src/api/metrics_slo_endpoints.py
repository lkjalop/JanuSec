from __future__ import annotations
from fastapi import APIRouter
from src.core.metrics.slo import current_slo_snapshot

router = APIRouter(prefix='/api/v1/metrics', tags=['Metrics'])

@router.get('/slo', summary='Return current SLO p95 latency snapshot')  # type: ignore[misc]
async def slo_snapshot() -> dict:
    return current_slo_snapshot()

__all__ = ['router']

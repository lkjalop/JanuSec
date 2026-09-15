"""Risk scoring API endpoints.

Provides:
  POST /api/v1/risk/score    -> body {"decision": {...}} returns risk composition
  GET  /api/v1/risk/score/{event_id} -> looks up decision in DECISION_CACHE and scores it
"""
from __future__ import annotations
from typing import Any, Dict
from fastapi import APIRouter, HTTPException

from .metrics_init import ensure_metrics

try:
    from src.core.risk_score import compose_risk_score  # advanced composer
except Exception:  # pragma: no cover
    compose_risk_score = None  # type: ignore
try:
    from src.core.threat_modeling.factor_taxonomy import compute_dread_score
except Exception:  # pragma: no cover
    compute_dread_score = None  # type: ignore

router = APIRouter()

def _score(decision: Dict[str, Any]) -> Dict[str, Any]:
    if not compose_risk_score:
        raise HTTPException(status_code=503, detail='risk_module_unavailable')
    # Compose (sync wrapper handles async path) and also observe unified Prometheus histogram if present
    result = compose_risk_score(decision)  # may call async internally
    try:
        ensure_metrics()
        from .metrics_init import risk_score_hist  # type: ignore
        if risk_score_hist:
            try:
                risk_score_hist.observe(float(result.get('score') or 0.0))
            except Exception:
                pass
    except Exception:
        pass
    return result  # already dict

@router.post('/api/v1/risk/score')
def risk_score_post(payload: Dict[str, Any]) -> Dict[str, Any]:
    dec = payload.get('decision')
    if not isinstance(dec, dict):
        raise HTTPException(status_code=400, detail='invalid_decision')
    return _score(dec)

@router.get('/api/v1/risk/score/{event_id}')
def risk_score_get(event_id: str) -> Dict[str, Any]:
    from .runtime_state import get_decision_cache
    DECISION_CACHE = get_decision_cache()
    decision = DECISION_CACHE.get(event_id)
    if not decision:
        raise HTTPException(status_code=404, detail='not_found')
    return _score(decision)

__all__ = ['router']


@router.post('/api/v1/risk/dread')
def dread_score(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Compute DREAD components and a normalized risk score.

    payload: { "factors": [..], "asset_criticality": 1.0, "exposure": 1.0 }
    """
    if not compute_dread_score:
        raise HTTPException(status_code=503, detail='dread_unavailable')
    factors = payload.get('factors') or []
    if not isinstance(factors, list):
        raise HTTPException(status_code=400, detail='invalid_factors')
    ac = float(payload.get('asset_criticality', 1.0) or 1.0)
    ex = float(payload.get('exposure', 1.0) or 1.0)
    return compute_dread_score(factors, asset_criticality=ac, exposure=ex)
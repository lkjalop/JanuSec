"""Endpoints exposing factor coverage and framework matrix.

Routes:
  GET /api/v1/factors/coverage
  GET /api/v1/factors/matrix  (query params: framework=mitre|stride|dread|pasta|cvss|controls)

Lightweight; uses public factor map from taxonomy without heavy processing.
"""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any, List
from src.core.threat_modeling.factor_taxonomy import FACTOR_MAP_PUBLIC

router = APIRouter(prefix="/api/v1/factors", tags=["Factors Coverage"])

_FRAMEWORK_KEYS = {
    'mitre': 'mitre',
    'stride': 'stride',
    'dread': 'dread',
    'maestro': 'maestro',
    'pasta': 'pasta_stage',
    'cvss': 'cvss',
    'controls': 'controls'
}

def _domain_of(factor: str) -> str:
    # domain prefix before first ':' or synthetic correlation/meta prefix
    if ':' in factor:
        return factor.split(':', 1)[0]
    if factor.startswith(('corr_','meta:')):
        return 'meta'
    return 'other'

@router.get('/coverage')
async def factor_coverage() -> Dict[str, Any]:
    total = len(FACTOR_MAP_PUBLIC)
    domains: Dict[str,int] = {}
    framework_counts = {k:0 for k in _FRAMEWORK_KEYS}
    for name, meta in FACTOR_MAP_PUBLIC.items():
        d = _domain_of(name)
        domains[d] = domains.get(d,0)+1
        for fw, key in _FRAMEWORK_KEYS.items():
            if key in meta and meta[key]:
                framework_counts[fw] += 1
    return {
        'total': total,
        'domains': domains,
        'framework_presence_counts': framework_counts,
        'framework_presence_percent': {k: round((v/max(1,total))*100,2) for k,v in framework_counts.items()},
    }

@router.get('/matrix')
async def factor_matrix(framework: str = Query('mitre')) -> Dict[str, Any]:
    fw = framework.lower().strip()
    if fw not in _FRAMEWORK_KEYS:
        raise HTTPException(status_code=400, detail='unsupported_framework')
    key = _FRAMEWORK_KEYS[fw]
    rows: List[Dict[str, Any]] = []
    for name, meta in FACTOR_MAP_PUBLIC.items():
        val = meta.get(key)
        if not val:
            continue
        rows.append({'factor': name, 'value': val})
    return {'framework': fw, 'count': len(rows), 'rows': rows}

__all__ = ['router']
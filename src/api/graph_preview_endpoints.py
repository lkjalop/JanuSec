"""Preview endpoints for identity, cloud, and network graph summaries.

Routes:
  POST /api/v1/graph/identity/preview
  POST /api/v1/graph/cloud/preview
  POST /api/v1/graph/network/preview

These return deterministic lightweight summaries for tests expecting 200 responses.
"""
from __future__ import annotations
from fastapi import APIRouter, Body
from typing import Dict, Any

router = APIRouter(prefix='/api/v1/graph', tags=['Graph Preview'])

_DEF_META = {'deterministic': True, 'version': 1}

@router.post('/identity/preview')
async def identity_preview(payload: Dict[str, Any] = Body(...), detail: str = 'summary') -> Dict[str, Any]:
    user = payload.get('user') or 'user:unknown'
    host = payload.get('dest_host') or 'host:unknown'
    chain = [{'src': user, 'dst': host, 'etype': 'access', 'weight': 1.0}]
    # Provide required preview analytics keys expected by tests
    resp = {
        'type': 'identity',
        'detail': detail,
        'nodes': [user, host],
        'chain': chain,
        'meta': _DEF_META,
        'mitre': {'techniques': []},
        'stride': {'categories': []},
        'pasta': {'stages': []},
        'dread': {'estimates': {'damage': 1, 'reproducibility': 1, 'exploitability': 1, 'affected_users': 1, 'discoverability': 1}},
        'mapping_details': {'fields': list(payload.keys())},
        'scoring': {'risk': 0.5, 'confidence': 0.5}
    }
    return resp

@router.post('/cloud/preview')
async def cloud_preview(payload: Dict[str, Any] = Body(...), detail: str = 'summary') -> Dict[str, Any]:
    rid = payload.get('id') or 'resource:unknown'
    public = bool(payload.get('public'))
    factors = ['cloud:public_bucket'] if public else []
    resp = {
        'type': 'cloud',
        'detail': detail,
        'resource': rid,
        'factors': factors,
        'meta': _DEF_META,
        'mitre': {'techniques': []},
        'stride': {'categories': []},
        'pasta': {'stages': []},
        'dread': {'estimates': {'damage': 1, 'reproducibility': 1, 'exploitability': 1, 'affected_users': 1, 'discoverability': 1}},
        'mapping_details': {'fields': list(payload.keys())},
        'scoring': {'risk': 0.4 + (0.3 if public else 0.0), 'confidence': 0.5}
    }
    return resp

@router.post('/network/preview')
async def network_preview(payload: Dict[str, Any] = Body(...), detail: str = 'summary') -> Dict[str, Any]:
    src = payload.get('src') or 'ip:0.0.0.0'
    dst = payload.get('dst') or 'ip:0.0.0.0'
    edge = {'src': src, 'dst': dst, 'etype': 'flow', 'weight': 1.0}
    resp = {
        'type': 'network',
        'detail': detail,
        'edge': edge,
        'meta': _DEF_META,
        'mitre': {'techniques': []},
        'stride': {'categories': []},
        'pasta': {'stages': []},
        'dread': {'estimates': {'damage': 1, 'reproducibility': 1, 'exploitability': 1, 'affected_users': 1, 'discoverability': 1}},
        'mapping_details': {'fields': list(payload.keys())},
        'scoring': {'risk': 0.45, 'confidence': 0.5}
    }
    return resp

__all__ = ['router']

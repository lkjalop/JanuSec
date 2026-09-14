from __future__ import annotations
from fastapi import APIRouter, HTTPException, Query
from typing import List

from src.core.mitre_ingest import load_local_techniques

router = APIRouter(prefix='/api/v1/mitre', tags=['MITRE'])


@router.get('/techniques/{tid}')
def get_technique(tid: str):
    techniques = load_local_techniques()
    t = techniques.get(tid)
    if not t:
        raise HTTPException(status_code=404, detail='technique_not_found')
    return t


@router.get('/techniques')
def list_techniques(q: str | None = Query(None), platform: str | None = Query(None), limit: int = 50):
    techniques = load_local_techniques()
    out: List[dict] = []
    for t in techniques.values():
        try:
            if q and q.lower() not in (t.get('name') or '').lower() and q.lower() not in (t.get('description') or '').lower():
                continue
            if platform and platform not in (t.get('platforms') or []):
                continue
            out.append({'id': t.get('id'), 'name': t.get('name'), 'platforms': t.get('platforms'), 'tactics': t.get('tactics')})
            if len(out) >= limit:
                break
        except Exception:
            continue
    return {'count': len(out), 'items': out}

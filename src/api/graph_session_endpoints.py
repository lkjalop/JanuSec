from fastapi import APIRouter, HTTPException, Depends, Body
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os, time, json

router = APIRouter(prefix="/api/v1/graph", tags=["GraphSession"])

class BuildSessionRequest(BaseModel):
    session_ids: List[str]
    correlate: Optional[bool] = True
    ewma: Optional[bool] = True
    ewma_alpha: Optional[float] = None
    mapping: Optional[Dict[str,str]] = None

@router.post('/session/build')
async def build_session(req: BuildSessionRequest):
    # Lightweight demo implementation: return a synthetic correlation matrix
    if not req.session_ids:
        raise HTTPException(status_code=400, detail='session_ids required')
    # Build dummy overlap counts proportional to length of id strings
    ids = req.session_ids
    n = len(ids)
    corr = [[0]*n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            if i==j:
                corr[i][j] = len(ids[i])
            else:
                corr[i][j] = max(1, (len(ids[i]) + len(ids[j])) % 5)
    resp = {
        'session_ids': ids,
        'correlation': corr,
        'correlation_smoothed': corr if req.ewma else None,
        'ewma_alpha': req.ewma_alpha or 0.6,
        'mapping_stats': {k: {'count': 1} for k in (req.mapping or {}).keys()},
        'factors': [],
        'verdict': 'info',
        'confidence': 0.35,
        'graph_summary': {'nodes': n, 'edges': sum(1 for i in range(n) for j in range(n) if i!=j)}
    }
    return resp

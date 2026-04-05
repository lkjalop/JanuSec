from __future__ import annotations
from fastapi import APIRouter, HTTPException, Header, Query, Depends
from typing import Optional, List
from src.ml.isolation_model import GLOBAL_ISO_MODEL
from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH as G
import os
from src.security.roles import require_roles

router = APIRouter(prefix="/api/v1/ml", tags=["ML Admin"], dependencies=[Depends(require_roles('admin'))])

ADMIN_KEY_ENV = "ADMIN_API_KEY"


def _check_admin(x_admin_key: Optional[str]):
    expected = os.environ.get(ADMIN_KEY_ENV)
    if expected and x_admin_key != expected:
        raise HTTPException(status_code=403, detail="forbidden")


def _valid_vector(v: List[float]) -> bool:
    # simple validation: must be numeric and finite
    try:
        if not isinstance(v, (list, tuple)):
            return False
        for x in v:
            if x is None:
                return False
            float(x)
        return True
    except Exception:
        return False


@router.post('/isolation/train')
async def train_isolation(
    x_admin_key: Optional[str] = Header(None),
    lookback: int = Query(1000, ge=1, le=100000),
    tenant: Optional[str] = Query(None),
    persist_path: Optional[str] = Query(None),
):
    _check_admin(x_admin_key)
    X: List[List[float]] = []
    try:
        # Gather recent per-identity events; prefer the most recent entries
        # G._recent_edges is a mapping identity -> deque of events
        items = list(G._recent_edges.items())
        # sort by most recent queue length (heuristic)
        items.sort(key=lambda it: len(it[1]) if it and it[1] else 0, reverse=True)
        for ident, dq in items:
            if tenant:
                # support identity names like tenant:userid or metadata on events
                if isinstance(ident, str) and not ident.startswith(f"{tenant}:"):
                    continue
            # build simple vector: [count, unique_hosts]
            cnt = len(dq)
            hosts = len(set(e.get('dst_host') for e in dq if e.get('dst_host')))
            vec = [float(cnt), float(hosts)]
            if _valid_vector(vec):
                X.append(vec)
            if len(X) >= lookback:
                break

        # ensure we have enough vectors
        if not X:
            return {'status': 'noop', 'trained': 0, 'reason': 'no-data'}

        # call training; allow admin to pass custom persistence path
        GLOBAL_ISO_MODEL.fit_partial(X, persist=True, path=persist_path)
        return {'status': 'ok', 'trained': len(X), 'model_saved': GLOBAL_ISO_MODEL.is_ready()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

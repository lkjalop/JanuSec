from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Path, Query

from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH as G


router = APIRouter(prefix="/api/v1/identity", tags=["Identity Reporting"])


@router.get("/summary")
async def identity_summary(user: str = Query(..., description="User id, e.g., user:alice@corp.com")) -> Dict[str, Any]:
    try:
        if not user.startswith('user:'):
            user = f'user:{user}'
        snap = G.identity_snapshot(user)
        return {'user': user, **snap}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"summary_error:{e}")


@router.get("/{user}/timeline")
async def identity_timeline(user: str = Path(..., description="User id, e.g., user:alice@corp.com"), limit: int = 50) -> Dict[str, Any]:
    try:
        if not user.startswith('user:'):
            user = f'user:{user}'
        snap = G.identity_snapshot(user)
        rows = list(snap.get('recent') or [])[:max(1, min(limit, 200))]
        return {'user': user, 'recent': rows}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"timeline_error:{e}")


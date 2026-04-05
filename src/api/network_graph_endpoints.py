from __future__ import annotations

from typing import Any, Dict, List
import time

from fastapi import APIRouter, HTTPException, Query

from src.core.graph.network_hopgraph import GLOBAL_NETWORK_GRAPH as NG
from src.core.graph.graph_scoring import compute_composite_score


router = APIRouter(prefix="/api/v1/graph/network", tags=["Network Graph"])


@router.post("/ingest")
async def ingest_network_flows(flows: List[Dict[str, Any]]) -> Dict[str, Any]:
    try:
        count = 0
        for f in flows or []:
            NG.ingest_flow(f)
            count += 1
        return {"status": "ok", "count": count}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid_payload:{e}")


@router.get("/paths")
async def network_paths(entry: str = Query(...), target: str = Query(...), limit: int = 10) -> Dict[str, Any]:
    try:
        paths = NG.find_paths(entry, target, limit=max(1, min(limit, 25)))
        enriched = []
        for p in paths:
            meta = NG.explain_path(p['path'])
            enriched.append({**p, **meta})
        return {"entry": entry, "target": target, "paths": enriched}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"query_error:{e}")


@router.post('/preview')
async def preview_network(payload: Dict[str, Any], detail: str | None = Query('summary')) -> Dict[str, Any]:
    try:
        # Accept either a single flow or list; choose first
        if isinstance(payload, list) and payload:
            f = payload[0]
        else:
            f = payload
        src = f.get('src') or f.get('source') or f.get('src_ip')
        dst = f.get('dst') or f.get('destination') or f.get('dst_ip')
        if not src or not dst:
            raise Exception('missing_src_or_dst')
        path = [f'ip:{src}', f'ip:{dst}']
        res = NG.explain_path(path)
        scoring = compute_composite_score(path, res.get('mapping_details') if isinstance(res, dict) else None, tenant=(f.get('tenant') if isinstance(f, dict) else None), ts=f.get('ts') if isinstance(f, dict) else None)
        out = {k: res[k] for k in ('mitre','stride','pasta','dread','mapping_details') if k in res}
        out['scoring'] = scoring
        out['diagnostic'] = {'preview_ts': time.time()}
        return out if detail == 'full' else out
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'preview_failed:{e}')


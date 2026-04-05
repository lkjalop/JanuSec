from __future__ import annotations

from typing import Any, Dict, List
import time

from fastapi import APIRouter, HTTPException, Query

from src.core.graph.cloud_hopgraph import GLOBAL_CLOUD_GRAPH as CG
from src.core.graph.graph_scoring import compute_composite_score


router = APIRouter(prefix="/api/v1/graph/cloud", tags=["Cloud Graph"])


@router.post("/ingest")
async def ingest_cloud_resources(resources: List[Dict[str, Any]]) -> Dict[str, Any]:
    try:
        for r in resources or []:
            CG.ingest_resource(r)
        return {"status": "ok", "count": len(resources or [])}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid_payload:{e}")


@router.get("/paths")
async def cloud_paths(entry: str = Query(...), target: str = Query(...), limit: int = 10) -> Dict[str, Any]:
    paths = CG.find_paths(entry, target, limit=max(1, min(limit, 25)))
    enriched = []
    for p in paths:
        meta = CG.explain_path(p['path'])
        enriched.append({**p, **meta})
    return {"entry": entry, "target": target, "paths": enriched}


@router.post("/ingest/aws_config")
async def ingest_aws_config(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to ingest common CSPM/AWS Config-like exports into CloudHopGraph.

    Accepts either a top-level {"resources": [...]} or a list payload. Each item is
    best-effort normalized into CloudHopGraph.ingest_resource schema:
      - id: arn or type:name
      - principals: list of principal strings (e.g., arn:aws:iam::...)
      - destinations: list of connected resource identifiers (cloud_resource:*) or plain ids
      - public: boolean if publicly exposed (e.g., internet reachable)
    """
    try:
        items = []
        if isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict):
            items = payload.get('resources') or payload.get('Items') or []
        count = 0
        for it in items:
            try:
                if not isinstance(it, dict):
                    continue
                arn = it.get('arn') or it.get('ARN') or it.get('resourceArn') or ''
                rtype = (it.get('type') or it.get('resourceType') or '').lower()
                name = it.get('name') or it.get('resourceName') or it.get('id') or it.get('resourceId') or ''
                rid = arn or (f"{rtype}:{name}" if (rtype and name) else (name or rtype))
                # principals: look in common places
                principals = []
                for k in ('principals','iam_principals','allowed_principals','assume_roles','roles','attached_roles'):
                    vals = it.get(k)
                    if isinstance(vals, (list, tuple)):
                        for v in vals:
                            if isinstance(v, str) and v not in principals:
                                principals.append(v)
                # Handle AWS Config-style relationships
                rel = it.get('relationships') or []
                if isinstance(rel, list):
                    for r in rel:
                        try:
                            p = r.get('principal') or r.get('source') or r.get('target')
                            if isinstance(p, str) and p.startswith('arn:') and p not in principals:
                                principals.append(p)
                        except Exception:
                            pass
                # destinations: network connected resources or edges
                destinations = []
                for k in ('destinations','connected','targets','edges'):
                    vals = it.get(k)
                    if isinstance(vals, (list, tuple)):
                        for v in vals:
                            s = str(v)
                            if s and s not in destinations:
                                destinations.append(s)
                # public flag heuristics
                public = bool(it.get('public') or it.get('isPublic') or it.get('internet_exposed'))
                # Security group style: any 0.0.0.0/0 ingress
                try:
                    sg = it.get('securityGroups') or it.get('ingress') or []
                    if isinstance(sg, list):
                        for rule in sg:
                            cidr = (rule.get('cidr') or rule.get('CidrIp') or '').strip()
                            if cidr == '0.0.0.0/0':
                                public = True
                                break
                except Exception:
                    pass
                CG.ingest_resource({
                    'id': rid,
                    'principals': principals,
                    'destinations': destinations,
                    'public': public,
                })
                count += 1
            except Exception:
                continue
        return {"status": "ok", "count": count}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid_payload:{e}")


@router.post('/preview')
async def preview_cloud(payload: Dict[str, Any], detail: str | None = Query('summary')) -> Dict[str, Any]:
    try:
        # Accept either a single resource or list; pick first resource for preview
        if isinstance(payload, list) and payload:
            r = payload[0]
        elif isinstance(payload, dict) and payload.get('resources'):
            r = (payload.get('resources') or [])[0]
        else:
            r = payload
        # Build a simple path: internet:* -> cloud_resource:id if public, else principal -> resource
        rid = r.get('id') or r.get('arn') or r.get('name') or 'cloud_resource:unknown'
        if r.get('public'):
            path = ['internet:*', f'cloud_resource:{rid}']
        else:
            principals = r.get('principals') or []
            if principals:
                path = [str(principals[0]), f'cloud_resource:{rid}']
            else:
                path = [f'cloud_resource:{rid}']
        res = CG.explain_path(path)
        scoring = compute_composite_score(path, res.get('mapping_details') if isinstance(res, dict) else None, tenant=(r.get('tenant') if isinstance(r, dict) else None))
        out = {k: res[k] for k in ('mitre','stride','pasta','dread','mapping_details') if k in res}
        out['scoring'] = scoring
        out['diagnostic'] = {'preview_ts': time.time()}
        return out if detail == 'full' else out
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'preview_failed:{e}')

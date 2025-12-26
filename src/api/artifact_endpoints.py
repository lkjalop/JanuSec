"""Artifact analysis endpoints separated from main server."""
from __future__ import annotations

import uuid
from typing import Any, List, Optional
import os

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel
try:
    from src.analysis.dread_scorer import score_dread  # type: ignore
except Exception:
    try:
        from analysis.dread_scorer import score_dread  # type: ignore
    except Exception:
        score_dread = None  # type: ignore

router = APIRouter()

class ArtifactBatch(BaseModel):  # type: ignore[misc]
    batch_id: str | None = None
    items: list[dict[str, Any]]
    tenant_id: str | None = None

_PIPELINE = None
def _get_pipeline():
    global _PIPELINE
    if _PIPELINE is None:
        try:
            # Prefer canonical src package implementation which provides process_batch
            try:
                from src.artifact.analyze import ArtifactPipeline
            except Exception:
                from artifact.analyze import ArtifactPipeline
            _PIPELINE = ArtifactPipeline()
        except Exception:
            class _Stub:
                def process_batch(self, items, batch_meta=None):
                    return [], {'error':'artifact_pipeline_unavailable'}
            _PIPELINE = _Stub()
    return _PIPELINE

@router.post('/api/v1/artifacts/analyze_batch')
async def analyze_artifact_batch(payload: ArtifactBatch):
    pipeline = _get_pipeline()
    try:
        items = payload.items or []
        results, meta = pipeline.process_batch(items, batch_meta={'batch_id': payload.batch_id or uuid.uuid4().hex})
        try:
            from artifact.report import serialize_artifact as _ser
            if results and not isinstance(results[0], dict):
                results = [_ser(r) for r in results]
        except Exception:
            pass
        # Ensure compatibility for clients/tests expecting a top-level `risk` field
        sanitized_results = []
        try:
            if isinstance(results, list):
                for a in results:
                    copy = None
                    # Try to coerce to a plain dict for reliable field injection
                    try:
                        copy = dict(a)
                    except Exception:
                        try:
                            copy = getattr(a, '__dict__', None)
                            if copy is not None:
                                copy = dict(copy)
                        except Exception:
                            copy = None
                    if isinstance(copy, dict):
                        if 'risk' not in copy:
                            if 'final_risk' in copy:
                                copy['risk'] = copy.get('final_risk')
                            elif 'base_risk' in copy:
                                copy['risk'] = copy.get('base_risk')
                            else:
                                copy['risk'] = copy.get('risk_confidence', 0.0)
                        sanitized_results.append(copy)
                    else:
                        sanitized_results.append(a)
            else:
                sanitized_results = results
        except Exception:
            sanitized_results = results

        report = {'all_artifacts': sanitized_results, 'duration': meta.get('duration'), 'vt_results': meta.get('vt_results')}
        return {'batch_id': payload.batch_id, 'report': report, 'meta': meta}
    except Exception as e:
        import traceback
        tb = traceback.format_exc(limit=5)
        raise HTTPException(status_code=500, detail=f"artifact_pipeline_error: {e}; trace={tb}")

__all__ = ['router']


# ---------------------- Artifact Listing Endpoint ----------------------
try:
    from .runtime_state import DECISION_CACHE  # type: ignore
except Exception:  # pragma: no cover
    DECISION_CACHE = {}

def _artifact_from_decision(dec_obj) -> dict:
    # Support both object-like decisions and plain dicts
    def _get(name, default=None):
        try:
            if isinstance(dec_obj, dict):
                return dec_obj.get(name, default)
            return getattr(dec_obj, name, default)
        except Exception:
            return default

    verdict = _get('verdict', 'UNKNOWN') or 'UNKNOWN'
    try:
        confidence = float(_get('confidence', 0.0) or 0.0)
    except Exception:
        confidence = 0.0
    try:
        factors = list(_get('factors', []) or [])
    except Exception:
        factors = []
    mitre = [f for f in factors if isinstance(f, str) and f.startswith('T')][:5]
    # Normalize factors into a mapping of factor->weight for DREAD scorer
    dread_factors: dict[str, float] = {}
    try:
        # factors may be list of strings or list of dicts
        if isinstance(factors, list):
            for f in factors:
                if isinstance(f, str):
                    dread_factors[f] = 1.0
                elif isinstance(f, dict):
                    k = f.get('type') or f.get('name') or f.get('factor')
                    v = f.get('weight') or f.get('score') or 1.0
                    if k:
                        try:
                            dread_factors[str(k)] = float(v)
                        except Exception:
                            dread_factors[str(k)] = 1.0
    except Exception:
        dread_factors = {}

    # Compute DREAD if scorer is available
    dread: dict | None = None
    dread_score = None
    dread_severity = None
    try:
        if score_dread is not None:
            d = score_dread(dread_factors)
            if isinstance(d, dict):
                dread = d
                # aggregate into a single score (mean of components)
                vals = [float(x) for x in d.values() if isinstance(x, (int, float))]
                if vals:
                    dread_score = sum(vals) / len(vals)
                    if dread_score >= 0.66:
                        dread_severity = 'high'
                    elif dread_score >= 0.33:
                        dread_severity = 'medium'
                    else:
                        dread_severity = 'low'
    except Exception:
        dread = None
        dread_score = None
        dread_severity = None

    return {
        'id': _get('event_id', None),
        'name': _get('event_id', None) or 'artifact',
        'type': 'EXECUTABLE',  # placeholder; future classification (network/tabular)
        'risk_score': int(confidence * 100),
        'verdict': verdict.lower(),
        'confidence': confidence,
        'mitre_tags': mitre or ['T1059'],
        'factors': factors[:15],
        'hash': _get('hash', None),
        'host_count': _get('host_count', 1) or 1,
        'dread': dread,
        'dread_score': dread_score,
        'dread_severity': dread_severity,
    'tenant_id': _get('tenant_id', None) or os.getenv('DEFAULT_TENANT','default')
    }

@router.get('/api/v1/artifacts/list')
async def artifacts_list(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    tenant_id: str | None = Query(None),
    x_tenant_header: str | None = Header(None, alias='X-Tenant-ID')
):
    # Header overrides query param if present
    if x_tenant_header:
        tenant_id = x_tenant_header
    items = list(DECISION_CACHE.values())
    len(items)
    # Reverse (recent first) assumption; DECISION_CACHE may be ordered insertion
    try:
        items = items[::-1]
    except Exception:
        pass
    artifacts: list[dict] = []
    for dec in items:
        if tenant_id and getattr(dec, 'tenant_id', None) != tenant_id:
            continue
        artifacts.append(_artifact_from_decision(dec))
    filtered_total = len(artifacts)
    slice_items = artifacts[offset: offset + limit]
    return {
        'artifacts': slice_items,
        'total': filtered_total,
        'limit': limit,
        'offset': offset,
        'tenant_id': tenant_id,
    }

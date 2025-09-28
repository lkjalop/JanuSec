"""Artifact analysis endpoints separated from main server."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any, List, Optional
import uuid

router = APIRouter()

class ArtifactBatch(BaseModel):
    batch_id: Optional[str] = None
    items: List[dict[str, Any]]
    tenant_id: Optional[str] = None

_PIPELINE = None
def _get_pipeline():
    global _PIPELINE
    if _PIPELINE is None:
        try:
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
        report = {'all_artifacts': results, 'duration': meta.get('duration'), 'vt_results': meta.get('vt_results')}
        return {'batch_id': payload.batch_id, 'report': report, 'meta': meta}
    except Exception as e:
        import traceback
        tb = traceback.format_exc(limit=5)
        raise HTTPException(status_code=500, detail=f"artifact_pipeline_error: {e}; trace={tb}")

__all__ = ['router']

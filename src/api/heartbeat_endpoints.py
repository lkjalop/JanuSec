from fastapi import APIRouter, HTTPException, Query, Request
from typing import List, Dict, Any
from pydantic import BaseModel
from src.core.heartbeat import record_ingest, get_actual_volume_last_hour, get_baseline_hourly, detect_missing_sources
from src.api.tenant_helpers import resolve_tenant_id

router = APIRouter(prefix="/api/v1/heartbeat", tags=["heartbeat"])


class IngestPayload(BaseModel):
    tenant_id: str
    source: str
    count: int = 1


@router.post('/ingest')
def ingest(payload: IngestPayload, request: Request):
    try:
        payload.tenant_id = resolve_tenant_id(request, payload.tenant_id) or payload.tenant_id
        record_ingest(payload.tenant_id, payload.source, count=payload.count)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/baseline/{tenant_id}/{source}')
def read_baseline(tenant_id: str, source: str, days: int = 7, request: Request = None):
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
        v = get_baseline_hourly(tenant_id, source, days=days)
        return {"tenant_id": tenant_id, "source": source, "baseline_hourly": v}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/anomalies/{tenant_id}')
def read_anomalies(tenant_id: str, sources: List[str] = Query(..., description='repeatable list of sources'), request: Request = None):
    # caller must pass sources as query param repeated: ?sources=sa&sources=sb
    try:
        tenant_id = resolve_tenant_id(request, tenant_id)
        res = detect_missing_sources(tenant_id, sources)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

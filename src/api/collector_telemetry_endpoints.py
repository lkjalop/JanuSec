from fastapi import APIRouter, Request, HTTPException
from typing import Dict, Any
from src.core.collector_telemetry import ingest_collector_telemetry

router = APIRouter()


@router.post('/api/v1/collector_telemetry')
async def post_collector_telemetry(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    cid = payload.get('collector_id') or payload.get('collector')
    if not cid:
        raise HTTPException(status_code=400, detail='missing_collector_id')
    try:
        ingest_collector_telemetry(cid, payload)
        return {'ok': True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

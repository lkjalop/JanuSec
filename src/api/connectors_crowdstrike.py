from fastapi import APIRouter, Header, HTTPException, Body, Request
from typing import Any, Dict, List, Optional

from src.api.runtime_state import (
    get_server_runtime_state,
    ingest_endpoint_events,
    persist_tenant_runtime,
)
from src.api.tenant_helpers import resolve_tenant_id


router = APIRouter(prefix="/api/v1/ingest", tags=["ingest-endpoint-xdr"])


def _normalize_crowdstrike_detection(d: Dict[str, Any]) -> Dict[str, Any]:
    evt: Dict[str, Any] = {
        'source': 'crowdstrike',
        'ts': d.get('ts') or d.get('timestamp'),
        'host': d.get('host') or d.get('aid') or (d.get('device', {}) or {}).get('hostname'),
        'user': d.get('user') or (d.get('actor', {}) or {}).get('name'),
        'process': d.get('process') or (d.get('raw', {}) or {}).get('ImageFileName'),
        'file_hash': (d.get('raw', {}) or {}).get('sha256') or d.get('sha256'),
        'severity': d.get('severity'),
        'id': d.get('id'),
        'observables': d.get('observables') or [],
        'raw': d,
    }
    return {k: v for k, v in evt.items() if v is not None}


@router.post('/endpoint')
async def ingest_endpoint(
    request: Request,
    payload: Dict[str, Any] = Body(...),
    tenant_id: Optional[str] = Header(None, alias='x-tenant-id'),
    api_key: Optional[str] = Header(None, alias='x-api-key'),
):
    if not api_key:
        raise HTTPException(status_code=401, detail='missing_api_key')
    runtime = get_server_runtime_state(request.app)
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or 'default'

    events: List[Dict[str, Any]] = []
    if isinstance(payload, dict) and 'detections' in payload:
        for d in payload['detections']:
            events.append(_normalize_crowdstrike_detection(d))
    elif isinstance(payload, dict) and 'events' in payload:
        for d in payload['events']:
            events.append(_normalize_crowdstrike_detection(d))
    else:
        events.append(_normalize_crowdstrike_detection(payload))

    tstate = runtime.tenants.setdefault(tenant, {})
    recents = tstate.setdefault('recent_endpoint_events', [])
    recents.extend(events)
    if len(recents) > 5000:
        del recents[:-5000]
    ingest_endpoint_events(runtime, events, tenant)
    persist_tenant_runtime(runtime, tenant)
    return {'ok': True, 'ingested': len(events)}

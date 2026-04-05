from fastapi import APIRouter, Header, HTTPException, UploadFile, File, Body, Request
from typing import Any, Dict, List, Optional

from src.connectors.sysmon_evtx import normalize_sysmon_event
from src.api.runtime_state import (
    get_server_runtime_state,
    persist_tenant_runtime,
    ingest_endpoint_events,
    update_connector_health,
)
from src.api.tenant_helpers import resolve_tenant_id


router = APIRouter(prefix="/api/v1/ingest", tags=["ingest-sysmon-wef"])


@router.post('/sysmon')
async def ingest_sysmon(
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
    if isinstance(payload, dict) and 'events' in payload:
        for evt in payload['events']:
            events.append(normalize_sysmon_event(evt))
    else:
        events.append(normalize_sysmon_event(payload))

    tstate = runtime.tenants.setdefault(tenant, {})
    recents = tstate.setdefault('recent_endpoint_events', [])
    recents.extend(events)
    if len(recents) > 5000:
        del recents[:-5000]
    ingest_endpoint_events(runtime, events, tenant)
    update_connector_health(runtime, tenant, 'endpoint:sysmon', provider='endpoint', status='ok', ok=True, last_count=len(events))
    persist_tenant_runtime(runtime, tenant)
    return {'ok': True, 'ingested': len(events)}


@router.post('/wef')
async def ingest_wef(
    request: Request,
    file: UploadFile = File(None),
    payload: Optional[Dict[str, Any]] = Body(None),
    tenant_id: Optional[str] = Header(None, alias='x-tenant-id'),
    api_key: Optional[str] = Header(None, alias='x-api-key'),
):
    if not api_key:
        raise HTTPException(status_code=401, detail='missing_api_key')
    runtime = get_server_runtime_state(request.app)
    tenant = tenant_id or 'default'
    events: List[Dict[str, Any]] = []

    if file is not None:
        data = await file.read()
        try:
            import json
            text = data.decode('utf-8', errors='ignore')
            for line in text.splitlines():
                if not line.strip():
                    continue
                evt = json.loads(line)
                events.append(normalize_sysmon_event(evt))
        except Exception:
            events.append({'source': 'wef', 'event': 'unparsed_evtx_payload', 'size': len(data)})
    elif payload is not None:
        if isinstance(payload, dict) and 'events' in payload:
            for evt in payload['events']:
                events.append(normalize_sysmon_event(evt))
        else:
            events.append(normalize_sysmon_event(payload))
    else:
        raise HTTPException(status_code=400, detail='missing_payload')

    tstate = runtime.tenants.setdefault(tenant, {})
    recents = tstate.setdefault('recent_endpoint_events', [])
    recents.extend(events)
    if len(recents) > 5000:
        del recents[:-5000]
    ingest_endpoint_events(runtime, events, tenant)
    update_connector_health(runtime, tenant, 'endpoint:wef', provider='endpoint', status='ok', ok=True, last_count=len(events))
    persist_tenant_runtime(runtime, tenant)
    return {'ok': True, 'ingested': len(events)}

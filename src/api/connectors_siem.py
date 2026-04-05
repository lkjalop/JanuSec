from fastapi import APIRouter, Header, HTTPException, Body, Request
from typing import Any, Dict, List, Optional

from src.api.runtime_state import get_server_runtime_state, persist_tenant_runtime
from src.api.tenant_helpers import resolve_tenant_id


router = APIRouter(prefix="/api/v1/ingest", tags=["ingest-siem"])


def _normalize_splunk(e: Dict[str, Any]) -> Dict[str, Any]:
    # Splunk webhook formats vary; support common event wrappers and HEC payloads
    evt = e.get('event') if isinstance(e.get('event'), dict) else e
    host = e.get('host') or evt.get('host')
    ts = e.get('time') or evt.get('_time') or evt.get('ts')
    msg = evt.get('message') or evt.get('_raw') or evt.get('raw')
    sourcetype = e.get('sourcetype') or evt.get('sourcetype')
    return {k: v for k, v in {
        'source': 'splunk',
        'ts': ts,
        'host': host,
        'sourcetype': sourcetype,
        'raw': evt,
        'message': msg,
    }.items() if v is not None}


def _normalize_elastic(e: Dict[str, Any]) -> Dict[str, Any]:
    # Elastic common schema (ECS) or webhook: pull standard fields
    host = (e.get('host') or {}).get('name') if isinstance(e.get('host'), dict) else e.get('host')
    ts = e.get('@timestamp') or e.get('timestamp') or e.get('ts')
    msg = e.get('message') or (e.get('log') or {}).get('original')
    event = e.get('event') or {}
    return {k: v for k, v in {
        'source': 'elastic',
        'ts': ts,
        'host': host,
        'event_kind': event.get('kind'),
        'event_category': event.get('category'),
        'event_type': event.get('type'),
        'message': msg,
        'raw': e,
    }.items() if v is not None}


@router.post('/splunk')
async def ingest_splunk(
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
        events = [_normalize_splunk(e) for e in payload.get('events') or []]
    else:
        events = [_normalize_splunk(payload)]
    tstate = runtime.tenants.setdefault(tenant, {})
    recents = tstate.setdefault('recent_siem_events', [])
    recents.extend(events)
    if len(recents) > 5000:
        del recents[:-5000]
    persist_tenant_runtime(runtime, tenant)
    return {'ok': True, 'ingested': len(events), 'accepted': len(events)}


@router.post('/elastic')
async def ingest_elastic(
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
        events = [_normalize_elastic(e) for e in payload.get('events') or []]
    else:
        events = [_normalize_elastic(payload)]
    tstate = runtime.tenants.setdefault(tenant, {})
    recents = tstate.setdefault('recent_siem_events', [])
    recents.extend(events)
    if len(recents) > 5000:
        del recents[:-5000]
    persist_tenant_runtime(runtime, tenant)
    return {'ok': True, 'ingested': len(events), 'accepted': len(events)}

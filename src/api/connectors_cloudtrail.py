from fastapi import APIRouter, Header, HTTPException, Body, Request
from typing import Any, Dict, List, Optional

from src.api.runtime_state import get_server_runtime_state, persist_tenant_runtime, update_connector_health
from src.api.tenant_helpers import resolve_tenant_id


router = APIRouter(prefix="/api/v1/ingest", tags=["ingest-cloudtrail"])


@router.post('/cloudtrail')
async def ingest_cloudtrail(
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
        events = [e for e in payload.get('events') or [] if isinstance(e, dict)]
    else:
        events = [payload]

    tstate = runtime.tenants.setdefault(tenant, {})
    recents = tstate.setdefault('recent_cloud_audit_events', [])
    recents.extend(events)
    if len(recents) > 5000:
        del recents[:-5000]
    update_connector_health(runtime, tenant, 'aws:cloudtrail', provider='aws', status='ok', ok=True, last_count=len(events))
    persist_tenant_runtime(runtime, tenant)
    return {'ok': True, 'ingested': len(events)}

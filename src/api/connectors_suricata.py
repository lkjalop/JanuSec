from fastapi import APIRouter, Header, HTTPException, Body, Request
from typing import Any, Dict, List, Optional

from src.api.runtime_state import get_server_runtime_state, persist_tenant_runtime
from src.api.tenant_helpers import resolve_tenant_id


router = APIRouter(prefix="/api/v1/ingest", tags=["ingest-suricata-eve"])


def _normalize_eve(e: Dict[str, Any]) -> Dict[str, Any]:
    evt = {
        'source': 'suricata',
        'ts': e.get('timestamp') or e.get('ts'),
        'host': e.get('host') or (e.get('flow', {}) or {}).get('src_ip'),
        'ip': e.get('src_ip'),
        'ip_dst': e.get('dest_ip') or e.get('dst_ip'),
        'alert': (e.get('alert') or {}).get('signature'),
        'severity': (e.get('alert') or {}).get('severity'),
        'category': (e.get('alert') or {}).get('category'),
        'proto': e.get('proto'),
        'raw': e,
    }
    return {k: v for k, v in evt.items() if v is not None}


@router.post('/suricata')
async def ingest_suricata(
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
        for e in payload['events']:
            events.append(_normalize_eve(e))
    else:
        events.append(_normalize_eve(payload))

    tstate = runtime.tenants.setdefault(tenant, {})
    recents = tstate.setdefault('recent_network_events', [])
    recents.extend(events)
    if len(recents) > 5000:
        del recents[:-5000]
    # Heartbeat: mark IDS/IPS as fresh when Suricata events arrive
    try:
        from src.core.monitoring.log_heartbeat import update as _hb_update  # type: ignore
    except Exception:
        try:
            from core.monitoring.log_heartbeat import update as _hb_update  # type: ignore
        except Exception:
            _hb_update = None  # type: ignore
    if _hb_update:
        try:
            _hb_update('ids_ips')
        except Exception:
            pass
    persist_tenant_runtime(runtime, tenant)
    return {'ok': True, 'ingested': len(events)}

from __future__ import annotations

import json
import os
import time
from fastapi import APIRouter, Request
from typing import Dict

from integrations.tenant_store import TenantStore
from integrations.polling_state import PollingStateStore
from ..tenant_helpers import resolve_tenant_id
from ..runtime_state import get_server_runtime_state, get_connector_health
from src.core.platform_scope import scope_allows_provider

router = APIRouter(prefix="/api/v1/connectors", tags=["connectors"])


@router.get("/{tenant_id}/{provider}/status")
def connector_status(tenant_id: str, provider: str, request: Request) -> Dict:
    if not scope_allows_provider(provider):
        return {
            "tenant": resolve_tenant_id(request, tenant_id),
            "provider": provider,
            "connected": False,
            "note": "provider_disabled_in_scope",
            "runtime_health": {},
        }
    tenant_id = resolve_tenant_id(request, tenant_id)
    runtime = get_server_runtime_state(request.app)
    runtime_health = get_connector_health(runtime, tenant_id)
    provider_health = {k: v for k, v in runtime_health.items() if str(k).startswith(f"{provider}:")}
    store = TenantStore()
    state = PollingStateStore()
    tokens = store.load_tokens(tenant_id)
    if tokens is None:
        return {
            "tenant": tenant_id,
            "provider": provider,
            "connected": False,
            "note": "no tokens persisted",
            "runtime_health": provider_health,
        }
    s = state.load_state(tenant_id, provider)
    expires_at = tokens.get("expires_at")
    return {
        "tenant": tenant_id,
        "provider": provider,
        "connected": True,
        "expires_at": expires_at,
        "state": s or {},
        "runtime_health": provider_health,
        "re_auth_url": os.environ.get(f"{provider.upper()}_REAUTH_URL") or None,
    }


@router.post("/{tenant_id}/{provider}/notify")
def connector_notify(tenant_id: str, provider: str, payload: dict, request: Request):
    """Accept operator alert notifications for a tenant/provider pair.

    This is a lightweight endpoint intended to be used by background workers
    to surface urgent tenant-level issues (token_revoked, circuit_open, quota_exceeded).
    """
    if not scope_allows_provider(provider):
        return {'status': 'ignored', 'reason': 'provider_disabled_in_scope'}
    tenant_id = resolve_tenant_id(request, tenant_id)
    note = payload.get('note') or 'alert'
    level = payload.get('level') or 'warning'
    # For demo: write a simple file under data/tenant_store/alerts
    try:
        # Prefer incidents aggregator if available so alerts surface in the platform
        try:
            from src.incidents.aggregator import GLOBAL_INCIDENTS
            if GLOBAL_INCIDENTS is not None:
                try:
                    GLOBAL_INCIDENTS.create_incident({
                        'tenant': tenant_id,
                        'domain': 'connectors',
                        'summary': f'Connector alert for {provider}',
                        'details': {'note': note, 'level': level},
                    })
                    return {'status': 'ok', 'ink': 'incident_created'}
                except Exception:
                    pass
        except Exception:
            pass
        # Fallback: write simple alert log
        root = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'tenant_store', 'alerts')
        os.makedirs(root, exist_ok=True)
        path = os.path.join(root, f"{tenant_id}_{provider}.log")
        with open(path, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps({'ts': int(time.time()), 'level': level, 'note': note}) + "\n")
    except Exception:
        pass
    return {'status': 'ok'}

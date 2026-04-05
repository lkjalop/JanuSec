from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request, Header
from pydantic import BaseModel, ConfigDict
from typing import Any, Dict, Optional, List

from src.core.correlation.rules import api_security as rules
from src.core.detectors.api_security import (
    analyze_api_event,
    get_inventory_snapshot,
    is_api_event,
    refresh_api_inventory_cache,
)
from src.monitoring.log_pull_contracts import get_contract
from .tenant_helpers import resolve_tenant_id

router = APIRouter(prefix='/api/v1/api_security', tags=['api_security'])

_COUNTS: Dict[str, int] = {k: 0 for k in rules.RULES.keys()}


class APIEvent(BaseModel):
    model_config = ConfigDict(extra="allow")
    uri: Optional[str] = None
    status: Optional[int] = None
    headers: Optional[Dict[str, Any]] = None
    params: Optional[Dict[str, Any]] = None
    body: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    auth_user: Optional[str] = None
    user: Optional[str] = None
    is_owner: Optional[bool] = None


class InventoryAssertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    observed_routes: List[str]


class GatewayLogBatch(BaseModel):
    model_config = ConfigDict(extra="allow")
    events: List[Dict[str, Any]]
    tenant_id: Optional[str] = None
    schema_version: Optional[str] = None
    format: Optional[str] = None


@router.post('/ingest')
async def ingest_api_event(ev: APIEvent) -> Dict[str, Any]:
    try:
        parsed = ev.dict()
        hits: List[str] = []
        for name, func in rules.RULES.items():
            try:
                if func(parsed):
                    _COUNTS[name] = _COUNTS.get(name, 0) + 1
                    hits.append(name)
            except Exception:
                continue

        # Run enhanced analyzer to surface structured findings
        enriched = analyze_api_event(parsed) if is_api_event(parsed) else None
        payload: Dict[str, Any] = {'status': 'ok', 'hits': hits}
        if enriched:
            payload['factors'] = enriched.factors
            payload['alerts'] = enriched.alerts
            payload['pii_matches'] = enriched.pii_matches
            payload['missing_logs'] = enriched.missing_logs
        return payload
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get('/summary')
async def summary(request: Request, tenant_id: Optional[str] = Header(None, alias='X-Tenant-ID')) -> Dict[str, Any]:
    tenant_id = resolve_tenant_id(request, tenant_id)
    return {'counts': dict(_COUNTS), 'tenant_id': tenant_id}


@router.get('/inventory')
async def inventory_snapshot(request: Request, tenant_id: Optional[str] = Header(None, alias='X-Tenant-ID')) -> Dict[str, Any]:
    """Return the current OpenAPI-backed inventory summary."""
    tenant_id = resolve_tenant_id(request, tenant_id)
    snapshot = get_inventory_snapshot()
    if isinstance(snapshot, dict):
        snapshot['tenant_id'] = tenant_id
    return snapshot


@router.post('/inventory/assert')
async def inventory_assert(request: InventoryAssertRequest) -> Dict[str, Any]:
    """Compare observed routes against the OpenAPI inventory."""
    snapshot = get_inventory_snapshot(request.observed_routes)
    snapshot['status'] = 'ok' if not snapshot['missing_routes'] else 'missing_routes'
    if snapshot['missing_routes']:
        raise HTTPException(status_code=400, detail=snapshot)
    return snapshot


@router.post('/inventory/reload')
async def inventory_reload() -> Dict[str, Any]:
    """Force refresh of the cached OpenAPI inventory."""
    refresh_api_inventory_cache()
    return {'status': 'reloaded', 'snapshot': get_inventory_snapshot()}


@router.post('/gateway_logs')
async def gateway_logs(payload: GatewayLogBatch, request: Request) -> Dict[str, Any]:
    """Ingest API gateway logs for authorization/business-flow analysis."""
    try:
        tenant_id = resolve_tenant_id(request, payload.tenant_id)
        contract = get_contract("api_gateway_logs") or {}
        export_format = (contract.get("export_format") or {}) if isinstance(contract, dict) else {}
        enforce_schema = os.getenv("API_GATEWAY_SCHEMA_ENFORCE", "0").lower() in {"1", "true", "yes"}
        expected_version = export_format.get("schema_version")
        expected_format = export_format.get("format")
        if enforce_schema and expected_version and not payload.schema_version:
            raise HTTPException(status_code=400, detail="schema_version_required")
        if payload.schema_version and expected_version and payload.schema_version != expected_version:
            raise HTTPException(status_code=400, detail="schema_version_mismatch")
        if enforce_schema and expected_format and not payload.format:
            raise HTTPException(status_code=400, detail="format_required")
        if payload.format and expected_format and payload.format != expected_format:
            raise HTTPException(status_code=400, detail="format_mismatch")
        events = payload.events or []
        total = len(events)
        factors: List[str] = []
        alerts: List[Dict[str, Any]] = []
        pii_hits: List[Dict[str, Any]] = []
        missing_logs: List[Dict[str, Any]] = []
        validation: Dict[str, Any] | None = None
        if export_format:
            required = list(dict.fromkeys((contract.get("required_fields") or []) + (export_format.get("fields") or [])))
            missing_fields: List[Dict[str, Any]] = []
            if required:
                for idx, ev in enumerate(events[:200]):
                    if not isinstance(ev, dict):
                        missing_fields.append({"index": idx, "missing": required})
                        continue
                    missing = [f for f in required if f not in ev]
                    if missing:
                        missing_fields.append({"index": idx, "missing": missing})
            if missing_fields:
                if enforce_schema:
                    raise HTTPException(status_code=400, detail={"error": "missing_fields", "missing": missing_fields})
                validation = {"missing_fields": missing_fields}
        for ev in events:
            parsed = dict(ev)
            if not is_api_event(parsed):
                continue
            enriched = analyze_api_event(parsed)
            if not enriched:
                continue
            factors.extend(enriched.factors or [])
            alerts.extend(enriched.alerts or [])
            pii_hits.extend(enriched.pii_matches or [])
            missing_logs.extend(enriched.missing_logs or [])
        return {
            'status': 'ok',
            'tenant_id': tenant_id,
            'ingested': total,
            'factors': factors,
            'alerts': alerts,
            'pii_matches': pii_hits,
            'missing_logs': missing_logs,
            'validation': validation,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

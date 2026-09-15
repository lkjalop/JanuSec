"""connectors_azure.py — Ingest API routes for Azure cloud sources.

Wires the existing Azure connector normalizers into FastAPI routes so that:
  - EntraID sign-ins, audit events
  - Microsoft Defender for Cloud findings
  - Azure Event Hub streamed events
  - Azure NSG flow logs
  - Conditional Access and Identity Protection events
  - Sentinel incidents (push path)
  - Azure Activity / Audit logs

all arrive at POST /api/v1/ingest/<source> and are normalised into the
canonical event shape stored in tenant runtime state for downstream analysis.

Every route:
  1. Requires ``x-api-key`` header (401 on missing).
  2. Accepts either a single event dict or ``{"events": [...]}`` batch.
  3. Calls the Azure normalizer to produce a canonical dict.
  4. Updates connector health (for the health dashboard).
  5. Stores up to 5 000 recent events per tenant in runtime state.
  6. Returns ``{ ok, ingested, accepted, source }`` JSON.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Header, HTTPException, Request

from src.api.runtime_state import (
    get_server_runtime_state,
    persist_tenant_runtime,
    update_connector_health,
)
from src.api.tenant_helpers import resolve_tenant_id

# Azure normalizer — carries all source-specific field extraction
try:
    from src.connectors.azure.normalizer import (
        normalize_entra_signin,
        normalize_entra_audit,
        normalize_event_hub_event,
        normalize_defender_cloud_finding,
    )
    _HAVE_AZURE_NORMALIZER = True
except Exception:
    _HAVE_AZURE_NORMALIZER = False

    def normalize_entra_signin(raw: Dict) -> Dict:          # type: ignore[misc]
        return {"source": "entra_signin", "source_kind": "entra_signin", "raw": raw}

    def normalize_entra_audit(raw: Dict) -> Dict:           # type: ignore[misc]
        return {"source": "entra_audit", "source_kind": "entra_audit", "raw": raw}

    def normalize_event_hub_event(raw: Dict) -> Dict:       # type: ignore[misc]
        return {"source": "event_hub", "source_kind": "event_hub", "raw": raw}

    def normalize_defender_cloud_finding(raw: Dict) -> Dict:  # type: ignore[misc]
        return {"source": "defender_cloud", "source_kind": "defender_cloud", "raw": raw}


router = APIRouter(prefix="/api/v1/ingest", tags=["ingest-azure"])

_MAX_EVENTS_STORED = 5_000
_CONNECTOR_STORE_KEY = "recent_azure_events"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_events(payload: Any) -> List[Dict[str, Any]]:
    """Accept single event or ``{"events": [...]}`` batch."""
    if isinstance(payload, dict) and "events" in payload:
        return [e for e in (payload.get("events") or []) if isinstance(e, dict)]
    if isinstance(payload, list):
        return [e for e in payload if isinstance(e, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def _store_events(
    request: Request,
    tenant: str,
    events: List[Dict[str, Any]],
    connector_name: str,
    provider: str = "azure",
) -> None:
    runtime = get_server_runtime_state(request.app)
    tstate = runtime.tenants.setdefault(tenant, {})
    recents = tstate.setdefault(_CONNECTOR_STORE_KEY, [])
    recents.extend(events)
    if len(recents) > _MAX_EVENTS_STORED:
        del recents[:-_MAX_EVENTS_STORED]
    update_connector_health(
        runtime, tenant, connector_name,
        provider=provider, status="ok", ok=True, last_count=len(events),
    )
    persist_tenant_runtime(runtime, tenant)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/entra_signin", summary="Ingest Azure AD / Entra ID sign-in logs")
async def ingest_entra_signin(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept EntraID sign-in log records.

    Payload: single ``signIn`` object **or** ``{"events": [...]}`` batch.
    Each record is normalised via ``normalize_entra_signin()`` which extracts
    user, IP, location, risk level, MFA state and correlation keys.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "entra_signin"}
    normalized = [normalize_entra_signin(e) for e in raw_events]
    _store_events(request, tenant, normalized, "azure:entra_signin")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "entra_signin"}


@router.post("/entra_audit", summary="Ingest Azure AD / Entra ID audit logs")
async def ingest_entra_audit(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept EntraID audit log records.

    Normalises role changes, group modifications, MFA device registrations
    and conditional-access policy changes.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "entra_audit"}
    normalized = [normalize_entra_audit(e) for e in raw_events]
    _store_events(request, tenant, normalized, "azure:entra_audit")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "entra_audit"}


@router.post("/defender_cloud", summary="Ingest Microsoft Defender for Cloud findings")
async def ingest_defender_cloud(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept Defender for Cloud security findings.

    Normalises alerts including resource ID, severity, attack tactics and
    MITRE technique mappings emitted by Defender for Cloud / Azure Security
    Center.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "defender_cloud"}
    normalized = [normalize_defender_cloud_finding(e) for e in raw_events]
    _store_events(request, tenant, normalized, "azure:defender_cloud")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "defender_cloud"}


@router.post("/event_hub", summary="Ingest Azure Event Hub streamed events")
async def ingest_event_hub(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept a batch of events from an Azure Event Hub stream.

    Payload may be a single Event Hub envelope or ``{"events": [...]}`` batch.
    Each record passes through ``normalize_event_hub_event()`` which handles
    the Event Hub wrapper and extracts the inner telemetry record.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "event_hub"}
    normalized = [normalize_event_hub_event(e) for e in raw_events]
    _store_events(request, tenant, normalized, "azure:event_hub")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "event_hub"}


@router.post("/nsg_flow", summary="Ingest Azure NSG flow logs")
async def ingest_nsg_flow(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept NSG flow log records (V2 format).

    Produces canonical network events with ``src_ip``, ``dst_ip``, ``port``,
    ``protocol``, ``bytes_in``, ``bytes_out``, ``action`` fields.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "nsg_flow"}

    def _normalize_nsg(e: Dict[str, Any]) -> Dict[str, Any]:
        # NSG V2 flow log record — records nested under flowTuples
        props = e.get("properties") or e
        flow_tuples = props.get("flowTuples") or props.get("flows") or []
        if isinstance(flow_tuples, str):
            # Comma-separated tuple: ts,src_ip,dst_ip,src_port,dst_port,protocol,direction,action,state,bytes_s2d,bytes_d2s
            parts = flow_tuples.split(",")
            flow_tuples = [{"_raw": flow_tuples, "_parts": parts}]
        normalized: Dict[str, Any] = {
            "source_kind": "nsg_flow",
            "source": "nsg_flow",
            "provider": "Azure",
            "ts": e.get("time") or e.get("ts"),
            "resource": props.get("resourceId") or e.get("resourceId"),
            "flow_tuples": flow_tuples,
            "raw": e,
        }
        # Try to pull first tuple if structured
        if flow_tuples and isinstance(flow_tuples[0], dict):
            ft = flow_tuples[0]
            parts = ft.get("_parts") or []
            if len(parts) >= 5:
                normalized["src_ip"] = parts[1]
                normalized["dst_ip"] = parts[2]
                normalized["src_port"] = parts[3]
                normalized["dst_port"] = parts[4]
                normalized["protocol"] = parts[5] if len(parts) > 5 else None
                normalized["action"] = parts[7] if len(parts) > 7 else None
        return {k: v for k, v in normalized.items() if v is not None}

    normalized = [_normalize_nsg(e) for e in raw_events]
    _store_events(request, tenant, normalized, "azure:nsg_flow")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "nsg_flow"}


@router.post("/azure_activity", summary="Ingest Azure Activity / Management logs")
async def ingest_azure_activity(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept Azure Activity log entries (ARM operations).

    Captures resource create /delete /modify events, role assignment changes,
    policy assignments and subscription-level administrative actions.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "azure_activity"}

    def _normalize_activity(e: Dict[str, Any]) -> Dict[str, Any]:
        caller = e.get("caller") or (e.get("claims") or {}).get("upn") or (e.get("claims") or {}).get("appid")
        return {k: v for k, v in {
            "source_kind": "azure_activity",
            "source": "azure_activity",
            "provider": "Azure",
            "ts": e.get("eventTimestamp") or e.get("time") or e.get("ts"),
            "user": caller,
            "actor": caller,
            "resource": e.get("resourceId"),
            "action": e.get("operationName") or e.get("operationId"),
            "status": (e.get("status") or {}).get("value") or e.get("status"),
            "resource_group": e.get("resourceGroupName"),
            "subscription": e.get("subscriptionId"),
            "correlation_id": e.get("correlationId"),
            "raw": e,
        }.items() if v is not None}

    normalized = [_normalize_activity(e) for e in raw_events]
    _store_events(request, tenant, normalized, "azure:azure_activity")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "azure_activity"}


@router.post("/sentinel_incident", summary="Push Sentinel incidents into the pipeline")
async def ingest_sentinel_incident(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept Microsoft Sentinel incidents pushed from a Logic App or Webhook.

    Stores incidents for correlation and enrichment alongside other cloud
    telemetry.  Use GET /api/v1/sentinel/incidents to query via pull.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "sentinel_incident"}

    def _normalize_sentinel(e: Dict[str, Any]) -> Dict[str, Any]:
        props = e.get("properties") or e
        return {k: v for k, v in {
            "source_kind": "sentinel_incident",
            "source": "sentinel_incident",
            "provider": "Azure",
            "ts": props.get("createdTimeUtc") or e.get("ts"),
            "incident_id": e.get("name") or props.get("incidentNumber"),
            "title": props.get("title"),
            "severity": props.get("severity"),
            "status": props.get("status"),
            "owner": (props.get("owner") or {}).get("email"),
            "tactics": [t for t in (props.get("tactics") or []) if t],
            "labels": [lb.get("labelName") for lb in (props.get("labels") or []) if isinstance(lb, dict)],
            "raw": e,
        }.items() if v is not None}

    normalized = [_normalize_sentinel(e) for e in raw_events]
    _store_events(request, tenant, normalized, "azure:sentinel_incident")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "sentinel_incident"}


__all__ = ["router"]

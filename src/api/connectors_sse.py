"""connectors_sse.py — Ingest API routes for SSE / cloud access proxy sources.

Wires Security Service Edge connectors into FastAPI routes:
  - Netskope (CASB, SWG, ZTNA event streams)
  - Zscaler (ZIA Internet Access + ZPA Private Access events)
  - Generic SSE / proxy catch-all

Every route:
  1. Requires ``x-api-key`` header (401 on missing).
  2. Accepts either a single event dict or ``{"events": [...]}`` batch.
  3. Normalises into the canonical event shape.
  4. Updates connector health for the health dashboard.
  5. Stores up to 5 000 recent events per tenant.
  6. Returns ``{ ok, ingested, accepted, source }`` JSON.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import asyncio
import logging
import os
import time

from fastapi import APIRouter, Body, Header, HTTPException, Request

from src.api.runtime_state import (
    get_server_runtime_state,
    persist_tenant_runtime,
    update_connector_health,
)
from src.api.tenant_helpers import resolve_tenant_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest-sse"])

_MAX_EVENTS_STORED = 5_000
_CONNECTOR_STORE_KEY = "recent_sse_events"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_events(payload: Any) -> List[Dict[str, Any]]:
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
    provider: str = "sse",
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
# Netskope
# ---------------------------------------------------------------------------

# Netskope event types and their mapped domain
_NETSKOPE_DOMAIN_MAP = {
    "application": "cloud",
    "alert":       "cloud",
    "connection":  "network",
    "page":        "network",
    "audit":       "cloud",
    "infrastructure": "endpoint",
}

_NETSKOPE_SEVERITY_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
    "unknown":  "info",
}

def _normalize_netskope(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a Netskope event (application, connection, alert types).

    Netskope delivers events with ``_inserttimestamp``, ``type`` and
    per-event-type fields.
    """
    evt_type = str(raw.get("type") or raw.get("event_type") or "").lower()
    domain = _NETSKOPE_DOMAIN_MAP.get(evt_type, "cloud")
    user = raw.get("user") or raw.get("useragent_string") or raw.get("srcip_hostname")
    app = raw.get("app") or raw.get("appcategory")
    activity = raw.get("activity") or raw.get("action")
    dst_host = raw.get("dst_hostname") or raw.get("dstip")
    src_ip = raw.get("srcip") or raw.get("client_ip")
    dst_ip = raw.get("dstip") or dst_host
    severity_raw = str(raw.get("alert_type") or raw.get("severity") or "info").lower()
    severity = _NETSKOPE_SEVERITY_MAP.get(severity_raw, "info")
    confidence = 0.78 if severity in ("critical", "high") else (0.55 if severity == "medium" else 0.35)
    dlp_rule = raw.get("dlp_rule") or raw.get("policy")
    threat_name = raw.get("malware_name") or raw.get("threat_name")
    factors = ["cloud:sse_netskope"]
    if dlp_rule:
        factors.append("data:dlp_rule_match")
    if threat_name:
        factors.append("cloud:threat_detected")
    # File/data movement
    file_name = raw.get("object") or raw.get("filename")
    file_size = raw.get("file_size") or raw.get("object_size")
    return {k: v for k, v in {
        "source_kind": "netskope",
        "source": "netskope",
        "provider": "Netskope",
        "domain": domain,
        "ts": raw.get("_inserttimestamp") or raw.get("timestamp") or raw.get("ts"),
        "event_type": evt_type,
        "user": user,
        "ip": src_ip,
        "src_ip": src_ip,
        "dst_ip": str(dst_ip) if dst_ip else None,
        "domain_name": raw.get("hostname") or dst_host,
        "resource": app,
        "action": activity,
        "app": app,
        "dlp_rule": dlp_rule,
        "threat_name": threat_name,
        "file_name": file_name,
        "file_size": file_size,
        "instance": raw.get("instance"),
        "policy": raw.get("policy"),
        "severity": severity,
        "confidence": confidence,
        "factors": factors,
        "raw": raw,
    }.items() if v is not None}


@router.post("/netskope", summary="Ingest Netskope CASB / SWG / ZTNA events")
async def ingest_netskope(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept Netskope event stream records.

    Handles application, connection, alert and audit event types.
    Extracts user, source IP, destination, app category, DLP rule matches
    and threat name for correlation with identity and cloud sources.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "netskope"}
    normalized = [_normalize_netskope(e) for e in raw_events]
    _store_events(request, tenant, normalized, "sse:netskope", provider="Netskope")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "netskope"}


# ---------------------------------------------------------------------------
# Zscaler
# ---------------------------------------------------------------------------

# Zscaler product categories
_ZSCALER_PRODUCT_DOMAIN = {
    "zia":  "network",
    "zpa":  "network",
    "zcc":  "endpoint",
    "zdx":  "endpoint",
    "zwa":  "cloud",
}


def _normalize_zscaler(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a Zscaler ZIA or ZPA log event.

    ZIA and ZPA share a broadly similar schema but differ in product-specific
    fields.  Both are normalised here to the same canonical shape.
    """
    product = str(raw.get("sourcetype") or raw.get("product") or raw.get("logtype") or "zia").lower()
    product_key = next((k for k in _ZSCALER_PRODUCT_DOMAIN if k in product), "zia")
    domain = _ZSCALER_PRODUCT_DOMAIN[product_key]

    # ZIA fields
    user = (raw.get("user") or raw.get("login") or raw.get("username") or
            raw.get("email") or raw.get("srcUser"))
    src_ip = raw.get("csip") or raw.get("clientip") or raw.get("srcip")
    dst_ip = raw.get("sdip") or raw.get("serverip") or raw.get("dstip")
    url = raw.get("url") or raw.get("requesturl")
    action = raw.get("action") or raw.get("urlaction") or raw.get("result")
    policy = raw.get("rulelabel") or raw.get("policy") or raw.get("policyname")
    threat = raw.get("malwareclass") or raw.get("threatname") or raw.get("virusname")
    category = raw.get("urlcategory") or raw.get("appcategory") or raw.get("category")
    bytes_total = (raw.get("requestsize") or 0) + (raw.get("responsesize") or 0)

    # ZPA fields (private access)
    app_group = raw.get("AppGroup") or raw.get("appgroup")
    app_name = raw.get("AppName") or raw.get("appname") or raw.get("application")
    connector = raw.get("Connector") or raw.get("connector")

    severity_raw = str(raw.get("severity") or "info").lower()
    is_blocked = str(action or "").lower() in {"block", "blocked", "drop"}
    has_threat = bool(threat)
    severity = "high" if (has_threat or is_blocked) else ("medium" if category else "info")
    confidence = 0.80 if has_threat else (0.65 if is_blocked else 0.40)
    factors = [f"cloud:sse_{product_key}"]
    if has_threat:
        factors.append("network:malware_detected")
    if is_blocked:
        factors.append("network:connection_blocked")

    resource = app_name or url or dst_ip
    return {k: v for k, v in {
        "source_kind": "zscaler",
        "source": "zscaler",
        "provider": "Zscaler",
        "domain": domain,
        "product": product_key.upper(),
        "ts": raw.get("datetime") or raw.get("timestamp") or raw.get("ts"),
        "user": user,
        "ip": src_ip,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "url": url,
        "resource": str(resource) if resource else None,
        "action": str(action) if action else None,
        "policy": policy,
        "category": category,
        "threat": threat,
        "app_group": app_group,
        "connector": connector,
        "bytes_total": bytes_total if bytes_total else None,
        "severity": severity,
        "confidence": confidence,
        "factors": factors,
        "raw": raw,
    }.items() if v is not None}


@router.post("/zscaler", summary="Ingest Zscaler ZIA / ZPA log events")
async def ingest_zscaler(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept Zscaler ZIA Internet Access or ZPA Private Access log events.

    Extracts user, source IP, URL, action (block/allow), policy rule, threat
    classification, app group and connector name.  High-signal events (threats
    or blocked connections) are tagged with elevated confidence.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "zscaler"}
    normalized = [_normalize_zscaler(e) for e in raw_events]
    _store_events(request, tenant, normalized, "sse:zscaler", provider="Zscaler")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "zscaler"}


# ---------------------------------------------------------------------------
# Generic SSE catch-all
# ---------------------------------------------------------------------------

@router.post("/sse", summary="Ingest generic SSE / proxy events")
async def ingest_sse_generic(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept generic SSE or proxy log events from sources without a dedicated route.

    Events must carry ``source_kind`` for proper downstream routing.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "sse_generic"}
    normalized = []
    for e in raw_events:
        if not e.get("source_kind"):
            e = dict(e)
            e["source_kind"] = "sse_generic"
            e["source"] = "sse_generic"
        normalized.append(e)
    _store_events(request, tenant, normalized, "sse:generic")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "sse_generic"}


# ---------------------------------------------------------------------------
# Splunk HEC normalizer
# ---------------------------------------------------------------------------
def _normalize_splunk(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a Splunk HEC event (wrapped in ``event`` key or raw)."""
    evt = raw.get("event") if isinstance(raw.get("event"), dict) else raw
    fields = raw.get("fields") or {}
    host = raw.get("host") or evt.get("host") or fields.get("host")
    src_ip = evt.get("src_ip") or evt.get("src") or fields.get("src_ip")
    dst_ip = evt.get("dest_ip") or evt.get("dest") or fields.get("dest_ip")
    user = evt.get("user") or evt.get("src_user") or fields.get("user")
    sev_raw = str(evt.get("severity") or fields.get("severity") or raw.get("severity") or "info").lower()
    severity = sev_raw if sev_raw in ("critical", "high", "medium", "low") else "info"
    source_type = raw.get("sourcetype") or raw.get("source") or "splunk"
    return {k: v for k, v in {
        "source_kind": "splunk",
        "source": source_type,
        "provider": "Splunk",
        "domain": "endpoint",
        "ts": raw.get("time") or evt.get("_time") or evt.get("timestamp"),
        "event_type": evt.get("EventCode") or evt.get("event_type") or source_type,
        "user": user,
        "host": host,
        "ip": src_ip,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "action": evt.get("action") or evt.get("EventType"),
        "process": evt.get("process") or evt.get("ParentCommandLine"),
        "file_hash": evt.get("file_hash") or evt.get("md5") or evt.get("sha256"),
        "severity": severity,
        "confidence": 0.7 if severity in ("critical", "high") else 0.45,
        "factors": ["endpoint:splunk_hec"],
        "raw": raw,
    }.items() if v is not None}


@router.post("/splunk", summary="Ingest Splunk HEC events")
async def ingest_splunk(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept Splunk HTTP Event Collector (HEC) formatted events."""
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "splunk"}
    normalized = [_normalize_splunk(e) for e in raw_events]
    _store_events(request, tenant, normalized, "sse:splunk", provider="Splunk")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "splunk"}


# ---------------------------------------------------------------------------
# Microsoft Sentinel normalizer
# ---------------------------------------------------------------------------
def _normalize_sentinel(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a Sentinel Log Analytics / Defender XDR event."""
    # Sentinel workspace events arrive with TimeGenerated, TenantId, Category, etc.
    user = (raw.get("AccountName") or raw.get("InitiatingProcessAccountName")
            or raw.get("SourceUserName") or raw.get("UserPrincipalName"))
    src_ip = raw.get("LocalIPAddress") or raw.get("SourceIP") or raw.get("RemoteIP")
    dst_ip = raw.get("RemoteIPAddress") or raw.get("DestinationIP")
    sev_raw = str(raw.get("Severity") or raw.get("AlertSeverity") or "informational").lower()
    _sev_map = {"high": "high", "medium": "medium", "low": "low",
                "critical": "critical", "informational": "info"}
    severity = _sev_map.get(sev_raw, "info")
    process = raw.get("InitiatingProcessFileName") or raw.get("ProcessName")
    file_hash = raw.get("SHA256") or raw.get("MD5") or raw.get("InitiatingProcessSHA256")
    entity = raw.get("DeviceName") or raw.get("ComputerName") or raw.get("HostName")
    return {k: v for k, v in {
        "source_kind": "sentinel",
        "source": raw.get("Category") or raw.get("AlertName") or "sentinel",
        "provider": "MicrosoftSentinel",
        "domain": "cloud",
        "ts": raw.get("TimeGenerated") or raw.get("CreatedTime") or raw.get("TimeStamp"),
        "event_type": raw.get("Category") or raw.get("Type") or "SentinelAlert",
        "entity": entity,
        "user": user,
        "ip": src_ip,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "action": raw.get("Activity") or raw.get("AlertName"),
        "process": process,
        "file_hash": file_hash,
        "description": (raw.get("Description") or raw.get("AlertDescription") or "")[:200],
        "severity": severity,
        "confidence": 0.75 if severity in ("critical", "high") else 0.5,
        "factors": ["cloud:sentinel_alert"],
        "raw": raw,
    }.items() if v is not None}


@router.post("/sentinel", summary="Ingest Microsoft Sentinel / Defender XDR alerts")
async def ingest_sentinel(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept Microsoft Sentinel Log Analytics or Defender XDR alert records."""
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "sentinel"}
    normalized = [_normalize_sentinel(e) for e in raw_events]
    _store_events(request, tenant, normalized, "sse:sentinel", provider="MicrosoftSentinel")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "sentinel"}


# ---------------------------------------------------------------------------
# Micro-batch pipeline flush
#
# Every CONNECTOR_FLUSH_INTERVAL_SECONDS the worker drains the per-tenant
# recent_sse_events store and submits a synthetic assessment through the same
# 6-stage pipeline used by manual uploads.  This turns live connector events
# into real persona-ready assessments without any UI change.
# ---------------------------------------------------------------------------
_FLUSH_INTERVAL: int = int(os.getenv("CONNECTOR_FLUSH_INTERVAL_SECONDS", "30"))
_FLUSH_MIN_EVENTS: int = int(os.getenv("CONNECTOR_FLUSH_MIN_EVENTS", "1"))
_FLUSH_TASK: asyncio.Task | None = None


async def _micro_batch_flush_worker(app_ref: Any) -> None:  # pragma: no cover
    """Background task: periodically flush connector events through the pipeline."""
    logger.info("Connector micro-batch flush worker started (interval=%ds)", _FLUSH_INTERVAL)
    while True:
        try:
            await asyncio.sleep(_FLUSH_INTERVAL)
            runtime = get_server_runtime_state(app_ref)
            for tenant, tstate in list(runtime.tenants.items()):
                events: list = tstate.get(_CONNECTOR_STORE_KEY) or []
                if len(events) < _FLUSH_MIN_EVENTS:
                    continue
                # Drain the queue
                batch = list(events)
                tstate[_CONNECTOR_STORE_KEY] = []

                # Submit through the deep-analyze pipeline
                try:
                    from src.api.deep_analyze_endpoints import (  # type: ignore
                        STAGE_REGISTRY, _get_trag_engine,
                    )
                    import uuid as _uuid
                    assessment_id = f"stream-{tenant}-{_uuid.uuid4().hex[:8]}"
                    context: dict = {
                        "rows": batch,
                        "assessment_id": assessment_id,
                        "org": tenant,
                        "tenant": tenant,
                        "source": "connector_stream",
                        "options": {"auto_llm": False},
                    }
                    stage_results = []
                    for stage in STAGE_REGISTRY:
                        try:
                            result = await stage.run(context)
                            stage_results.append(result)
                        except Exception as exc:
                            stage_results.append({"stage": stage.name, "status": "error", "error": str(exc)})
                    # Also index into TemporalRAG corpus
                    engine = _get_trag_engine()
                    if engine:
                        await asyncio.to_thread(engine.index_rows, batch, tenant)
                    logger.info(
                        "Connector flush: tenant=%s events=%d assessment_id=%s",
                        tenant, len(batch), assessment_id,
                    )
                except Exception as exc:
                    logger.warning("Connector micro-batch pipeline error: %s", exc)
        except asyncio.CancelledError:
            logger.info("Connector micro-batch flush worker stopped")
            return
        except Exception as exc:
            logger.warning("Connector flush worker error: %s", exc)


def start_flush_worker(app: Any) -> None:  # pragma: no cover
    """Start the background flush task (call from app lifespan / startup)."""
    global _FLUSH_TASK
    if _FLUSH_INTERVAL <= 0:
        return
    if _FLUSH_TASK is None or _FLUSH_TASK.done():
        _FLUSH_TASK = asyncio.create_task(_micro_batch_flush_worker(app))


__all__ = ["router", "start_flush_worker"]

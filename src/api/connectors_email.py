"""connectors_email.py — Ingest API routes for email security sources.

Wires email security connectors into FastAPI routes:
  - Proofpoint TAP (click and message events)
  - Microsoft Graph (mail flow events)
  - Mimecast (threat intelligence feed)
  - Abnormal Security alerts
  - Cofense Vision phishing intelligence
  - Generic email/phishing ingest path

Every route:
  1. Requires ``x-api-key`` header (401 on missing).
  2. Accepts either a single event dict or ``{"events": [...]}`` batch.
  3. Normalises into the canonical email event shape.
  4. Updates connector health for the health dashboard.
  5. Stores up to 5 000 recent events per tenant.
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

router = APIRouter(prefix="/api/v1/ingest/email", tags=["ingest-email"])

_MAX_EVENTS_STORED = 5_000
_CONNECTOR_STORE_KEY = "recent_email_events"


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
) -> None:
    runtime = get_server_runtime_state(request.app)
    tstate = runtime.tenants.setdefault(tenant, {})
    recents = tstate.setdefault(_CONNECTOR_STORE_KEY, [])
    recents.extend(events)
    if len(recents) > _MAX_EVENTS_STORED:
        del recents[:-_MAX_EVENTS_STORED]
    update_connector_health(
        runtime, tenant, connector_name,
        provider="email", status="ok", ok=True, last_count=len(events),
    )
    persist_tenant_runtime(runtime, tenant)


# ---------------------------------------------------------------------------
# Proofpoint TAP
# ---------------------------------------------------------------------------

def _normalize_proofpoint(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise Proofpoint TAP click or message event."""
    # TAP delivers two event types: messagesDelivered / clicksPermitted
    evt_type = raw.get("type") or ("click" if "clickTime" in raw else "message")
    recipients = raw.get("recipient") or raw.get("recipients") or []
    if isinstance(recipients, str):
        recipients = [recipients]
    sender = raw.get("sender") or raw.get("fromAddress")
    subject = raw.get("subject")
    threat = raw.get("threatsInfoMap") or raw.get("classification") or []
    threat_names = []
    if isinstance(threat, list):
        threat_names = [t.get("threatType") or t.get("threat") for t in threat if isinstance(t, dict)]
    elif isinstance(threat, str):
        threat_names = [threat]
    url = raw.get("url") or (threat[0].get("threat") if isinstance(threat, list) and threat else None)
    return {k: v for k, v in {
        "source_kind": "proofpoint",
        "source": "proofpoint",
        "provider": "Proofpoint",
        "domain": "email",
        "ts": raw.get("clickTime") or raw.get("messageTime") or raw.get("ts"),
        "event_type": evt_type,
        "user": recipients[0] if recipients else None,
        "recipients": recipients,
        "sender": sender,
        "subject": subject,
        "url": url,
        "threat_names": [n for n in threat_names if n],
        "guid": raw.get("GUID") or raw.get("guid") or raw.get("messageID"),
        "severity": "high" if threat_names else "medium",
        "confidence": 0.80 if threat_names else 0.55,
        "factors": ["email:proofpoint_tap"] + (["email:threat_click"] if evt_type == "click" else []),
        "raw": raw,
    }.items() if v is not None}


@router.post("/proofpoint", summary="Ingest Proofpoint TAP click and message events")
async def ingest_proofpoint(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept Proofpoint TAP events.

    Payload may deliver either ``clicksPermitted`` or ``messagesDelivered``
    event batches.  Threat classifications and click URLs are extracted for
    correlation with identity and network sources.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "proofpoint"}
    normalized = [_normalize_proofpoint(e) for e in raw_events]
    _store_events(request, tenant, normalized, "email:proofpoint")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "proofpoint"}


# ---------------------------------------------------------------------------
# Microsoft Graph — mail events
# ---------------------------------------------------------------------------

def _normalize_graph_mail(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise MS Graph mail event or Defender alert for email."""
    sender = (raw.get("from") or raw.get("sender") or {})
    if isinstance(sender, dict):
        sender_email = (sender.get("emailAddress") or sender.get("email") or {})
        sender_str = sender_email.get("address") if isinstance(sender_email, dict) else str(sender_email)
    else:
        sender_str = str(sender)
    recipients = []
    for field in ("toRecipients", "to", "recipients"):
        rec = raw.get(field) or []
        if isinstance(rec, list):
            for r in rec:
                if isinstance(r, dict):
                    email_addr = (r.get("emailAddress") or r.get("email") or {})
                    addr = email_addr.get("address") if isinstance(email_addr, dict) else str(email_addr)
                    if addr:
                        recipients.append(addr)
                elif isinstance(r, str):
                    recipients.append(r)
        if recipients:
            break
    internet_msg_id = raw.get("internetMessageId") or raw.get("messageId") or raw.get("id")
    threat_types = raw.get("threatTypes") or raw.get("detectionMethods") or []
    return {k: v for k, v in {
        "source_kind": "microsoft_graph_email",
        "source": "microsoft_graph_email",
        "provider": "Microsoft",
        "domain": "email",
        "ts": raw.get("receivedDateTime") or raw.get("createdDateTime") or raw.get("ts"),
        "user": recipients[0] if recipients else None,
        "recipients": recipients,
        "sender": sender_str,
        "subject": raw.get("subject"),
        "message_id": internet_msg_id,
        "threat_types": threat_types,
        "delivery_action": raw.get("deliveryAction"),
        "phish_confidence": float(raw.get("phishConfidence") or 0),
        "severity": ("high" if threat_types else "info"),
        "confidence": 0.75 if threat_types else 0.40,
        "factors": ["email:graph_mail"] + (["email:threat_detected"] if threat_types else []),
        "raw": raw,
    }.items() if v is not None}


@router.post("/graph", summary="Ingest Microsoft Graph mail events")
async def ingest_graph_mail(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept Microsoft Graph mail events or Defender for Office 365 alerts.

    Extracts sender, recipients, subject, threat type and delivery action for
    correlation with identity and endpoint sources.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "microsoft_graph_email"}
    normalized = [_normalize_graph_mail(e) for e in raw_events]
    _store_events(request, tenant, normalized, "email:graph")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "microsoft_graph_email"}


# ---------------------------------------------------------------------------
# Mimecast
# ---------------------------------------------------------------------------

def _normalize_mimecast(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise Mimecast SIEM API event."""
    # Mimecast SIEM feed delivers per-event dicts with snake_case or camelCase
    sender = raw.get("Sender") or raw.get("sender") or raw.get("senderAddress") or raw.get("from")
    recipients_raw = raw.get("Recipients") or raw.get("recipients") or raw.get("to") or []
    if isinstance(recipients_raw, str):
        recipients_raw = [recipients_raw]
    act = raw.get("Act") or raw.get("act") or raw.get("action")
    return {k: v for k, v in {
        "source_kind": "mimecast",
        "source": "mimecast",
        "provider": "Mimecast",
        "domain": "email",
        "ts": raw.get("Datetime") or raw.get("datetime") or raw.get("ts"),
        "user": recipients_raw[0] if recipients_raw else None,
        "sender": sender,
        "subject": raw.get("Subject") or raw.get("subject"),
        "action": act,
        "reason": raw.get("Reason") or raw.get("reason"),
        "threat_category": raw.get("Category") or raw.get("threatCategory"),
        "severity": ("high" if str(act or "").upper() in {"BLOCK", "REJECT"} else "medium"),
        "confidence": 0.78 if str(act or "").upper() in {"BLOCK", "REJECT"} else 0.50,
        "factors": ["email:mimecast"] + (["email:blocked"] if str(act or "").upper() == "BLOCK" else []),
        "raw": raw,
    }.items() if v is not None}


@router.post("/mimecast", summary="Ingest Mimecast threat events")
async def ingest_mimecast(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept Mimecast SIEM API events.

    Captures sender, recipients, action (BLOCK/ALLOW/REJECT),
    threat category and reason.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "mimecast"}
    normalized = [_normalize_mimecast(e) for e in raw_events]
    _store_events(request, tenant, normalized, "email:mimecast")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "mimecast"}


# ---------------------------------------------------------------------------
# Abnormal Security
# ---------------------------------------------------------------------------

def _normalize_abnormal(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise Abnormal Security threat alert."""
    attackers = raw.get("attackerEmailAddress") or raw.get("from") or ""
    recipient = raw.get("recipientEmailAddress") or raw.get("to") or ""
    threat_id = raw.get("threatId") or raw.get("threatID") or raw.get("id")
    attack_strategy = raw.get("attackStrategy") or raw.get("threatType") or raw.get("attackType")
    severity = str(raw.get("threatScore") or 0)
    try:
        sev_score = float(severity)
        sev_label = "critical" if sev_score >= 90 else ("high" if sev_score >= 70 else "medium")
        confidence = sev_score / 100.0
    except Exception:
        sev_label = "medium"
        confidence = 0.65
    return {k: v for k, v in {
        "source_kind": "abnormal",
        "source": "abnormal",
        "provider": "Abnormal",
        "domain": "email",
        "ts": raw.get("firstObserved") or raw.get("receivedTime") or raw.get("ts"),
        "user": str(recipient) if recipient else None,
        "sender": str(attackers) if attackers else None,
        "subject": raw.get("subject"),
        "threat_id": str(threat_id) if threat_id else None,
        "attack_strategy": attack_strategy,
        "impersonated_party": raw.get("impersonatedParty"),
        "severity": sev_label,
        "confidence": confidence,
        "factors": ["email:abnormal_detection", "email:bec_risk"],
        "raw": raw,
    }.items() if v is not None}


@router.post("/abnormal", summary="Ingest Abnormal Security alerts")
async def ingest_abnormal(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept Abnormal Security threat alerts.

    Extracts attacker email, recipient, attack strategy, threat score and
    impersonated party for BEC / social engineering correlation.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "abnormal"}
    normalized = [_normalize_abnormal(e) for e in raw_events]
    _store_events(request, tenant, normalized, "email:abnormal")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "abnormal"}


# ---------------------------------------------------------------------------
# Cofense Vision
# ---------------------------------------------------------------------------

def _normalize_cofense(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise Cofense Vision phishing intelligence report."""
    reporter = raw.get("reporter") or raw.get("reportedBy") or {}
    reporter_email = reporter.get("emailAddress") if isinstance(reporter, dict) else str(reporter)
    location = raw.get("location") or raw.get("attackType")
    return {k: v for k, v in {
        "source_kind": "cofense",
        "source": "cofense",
        "provider": "Cofense",
        "domain": "email",
        "ts": raw.get("receivedOn") or raw.get("reportedOn") or raw.get("ts"),
        "user": reporter_email,
        "subject": raw.get("subject"),
        "location": location,
        "cluster_id": raw.get("clusterId") or raw.get("reportId"),
        "severity": "high" if location else "medium",
        "confidence": 0.70,
        "factors": ["email:cofense_report", "email:user_reported"],
        "raw": raw,
    }.items() if v is not None}


@router.post("/cofense", summary="Ingest Cofense Vision phishing reports")
async def ingest_cofense(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept Cofense Vision analyst or user-reported phishing incidents.

    Captures reporter, subject, attack-type classification and cluster ID for
    phishing campaign correlation.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "cofense"}
    normalized = [_normalize_cofense(e) for e in raw_events]
    _store_events(request, tenant, normalized, "email:cofense")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "cofense"}


# ---------------------------------------------------------------------------
# Generic email / phishing catch-all
# ---------------------------------------------------------------------------

@router.post("/generic", summary="Ingest generic email threat events")
async def ingest_email_generic(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept generic email events from sources not covered by a specific route.

    Any field that carries ``source_kind`` will be preserved.  Without it the
    event is stored with ``source_kind=email_generic`` for manual review.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "email_generic"}
    normalized = []
    for e in raw_events:
        if not e.get("source_kind"):
            e = dict(e)
            e["source_kind"] = "email_generic"
            e["source"] = "email_generic"
        normalized.append(e)
    _store_events(request, tenant, normalized, "email:generic")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "email_generic"}


__all__ = ["router"]

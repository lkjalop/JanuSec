"""connectors_aws.py — Ingest API routes for AWS cloud sources.

Wires the existing AWS connector normalizers into FastAPI routes so that:
  - GuardDuty findings
  - VPC Flow log records
  - Security Hub aggregated findings
  - IAM change events (via CloudTrail filter)
  - S3 access log entries
  - CloudWatch metric alarms and log events
  - AWS Config resource state snapshots

all arrive at POST /api/v1/ingest/<source> and are normalised into the
canonical event shape for downstream analysis.

Every route:
  1. Requires ``x-api-key`` header (401 on missing).
  2. Accepts either a single event dict or ``{"events": [...]}`` batch.
  3. Updates connector health for the health dashboard.
  4. Stores up to 5 000 recent events per tenant.
  5. Returns ``{ ok, ingested, accepted, source }`` JSON.
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

# AWS canonical envelope helper
try:
    from src.connectors.aws.base import canonical_envelope as _aws_canonical_envelope
    _HAVE_AWS_BASE = True
except Exception:
    _HAVE_AWS_BASE = False

    def _aws_canonical_envelope(raw: Dict, source: str, account_id: str = "", region: str = "") -> Dict:  # type: ignore[misc]
        return {"source": source, "source_kind": source, "account_id": account_id, "region": region, "raw": raw}


router = APIRouter(prefix="/api/v1/ingest", tags=["ingest-aws"])

_MAX_EVENTS_STORED = 5_000
_CONNECTOR_STORE_KEY = "recent_aws_events"


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


def _account_region(payload: Any) -> tuple:
    if isinstance(payload, dict):
        return payload.get("account_id") or payload.get("accountId") or "", payload.get("region") or ""
    return "", ""


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
        provider="aws", status="ok", ok=True, last_count=len(events),
    )
    persist_tenant_runtime(runtime, tenant)


# ---------------------------------------------------------------------------
# GuardDuty
# ---------------------------------------------------------------------------

def _normalize_guardduty(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map a GuardDuty finding object to a canonical event dict."""
    service = raw.get("Service") or raw.get("service") or {}
    action = service.get("Action") or service.get("action") or {}
    network = action.get("NetworkConnectionAction") or action.get("networkConnectionAction") or {}
    remote_ip_info = network.get("RemoteIpDetails") or network.get("remoteIpDetails") or {}
    remote_ip = remote_ip_info.get("IpAddressV4") or remote_ip_info.get("ipAddressV4")
    resource = raw.get("Resource") or raw.get("resource") or {}
    iam_principal = (resource.get("AccessKeyDetails") or resource.get("accessKeyDetails") or {})
    user = iam_principal.get("UserName") or iam_principal.get("userName")
    # Map GuardDuty severity (1-10) to label
    gd_severity = float(raw.get("Severity") or raw.get("severity") or 0)
    sev_label = "critical" if gd_severity >= 7 else ("high" if gd_severity >= 4 else "medium")
    return {k: v for k, v in {
        "source_kind": "guardduty",
        "source": "guardduty",
        "provider": "AWS",
        "ts": raw.get("UpdatedAt") or raw.get("CreatedAt") or raw.get("ts"),
        "finding_id": raw.get("Id") or raw.get("id"),
        "type": raw.get("Type") or raw.get("type"),
        "title": raw.get("Title") or raw.get("title"),
        "severity": sev_label,
        "confidence": min(1.0, gd_severity / 10.0),
        "user": user,
        "ip": remote_ip,
        "resource": str(resource.get("ResourceType") or resource.get("resourceType") or ""),
        "account_id": raw.get("AccountId") or raw.get("accountId"),
        "region": raw.get("Region") or raw.get("region"),
        "factors": ["cloud:provider_detection"],
        "raw": raw,
    }.items() if v is not None}


@router.post("/guardduty", summary="Ingest AWS GuardDuty findings")
async def ingest_guardduty(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept AWS GuardDuty findings.

    Payload: single finding object or ``{"events": [...]}`` batch.
    Normalises severity (1-10 scale) to canonical ``critical/high/medium``,
    extracts actor identity, remote IP, and resource type.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "guardduty"}
    normalized = [_normalize_guardduty(e) for e in raw_events]
    _store_events(request, tenant, normalized, "aws:guardduty")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "guardduty"}


# ---------------------------------------------------------------------------
# VPC Flow Logs
# ---------------------------------------------------------------------------

def _normalize_vpcflow(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map a VPC Flow log record to a canonical event dict."""
    # Supports both parsed-dict form and raw space-delimited string form
    if isinstance(raw, str):
        parts = raw.split()
        keys = ("version", "account_id", "interface_id", "srcaddr", "dstaddr",
                "srcport", "dstport", "protocol", "packets", "bytes",
                "start", "end", "action", "log_status")
        raw = dict(zip(keys, parts))
    return {k: v for k, v in {
        "source_kind": "vpcflow",
        "source": "vpcflow",
        "provider": "AWS",
        "ts": raw.get("start") or raw.get("ts"),
        "src_ip": raw.get("srcaddr") or raw.get("src_ip"),
        "dst_ip": raw.get("dstaddr") or raw.get("dst_ip"),
        "src_port": raw.get("srcport") or raw.get("src_port"),
        "dst_port": raw.get("dstport") or raw.get("dst_port"),
        "protocol": raw.get("protocol"),
        "bytes_sent": raw.get("bytes"),
        "packets": raw.get("packets"),
        "action": raw.get("action"),
        "interface_id": raw.get("interface_id"),
        "account_id": raw.get("account_id"),
        "factors": ["network:flow_record"],
        "raw": raw,
    }.items() if v is not None}


@router.post("/vpcflow", summary="Ingest AWS VPC Flow log records")
async def ingest_vpcflow(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept VPC Flow log records.

    Supports parsed-dict form (from CloudWatch Logs Insights) or space-delimited
    string form.  Extracts src/dst IP, ports, protocol, bytes, and flow action.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "vpcflow"}
    normalized = [_normalize_vpcflow(e) for e in raw_events]
    _store_events(request, tenant, normalized, "aws:vpcflow")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "vpcflow"}


# ---------------------------------------------------------------------------
# Security Hub
# ---------------------------------------------------------------------------

def _normalize_securityhub(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map a Security Hub ASFF finding to a canonical event dict."""
    severity = (raw.get("Severity") or raw.get("severity") or {})
    sev_label = str(severity.get("Label") or severity.get("label") or "MEDIUM").lower()
    resources = raw.get("Resources") or raw.get("resources") or []
    resource_id = resources[0].get("Id") or resources[0].get("id") if resources else None
    compliance = raw.get("Compliance") or raw.get("compliance") or {}
    return {k: v for k, v in {
        "source_kind": "securityhub",
        "source": "securityhub",
        "provider": "AWS",
        "ts": raw.get("UpdatedAt") or raw.get("CreatedAt") or raw.get("ts"),
        "finding_id": raw.get("Id") or raw.get("id"),
        "title": raw.get("Title") or raw.get("title"),
        "severity": sev_label,
        "confidence": float((raw.get("Confidence") or raw.get("confidence") or 50)) / 100.0,
        "resource": resource_id,
        "account_id": raw.get("AwsAccountId") or raw.get("awsAccountId"),
        "region": raw.get("Region") or raw.get("region"),
        "compliance_status": compliance.get("Status") or compliance.get("status"),
        "generator_id": raw.get("GeneratorId") or raw.get("generatorId"),
        "product_name": (raw.get("ProductFields") or {}).get("aws/securityhub/ProductName"),
        "factors": ["cloud:provider_detection", "cloud:security_hub"],
        "raw": raw,
    }.items() if v is not None}


@router.post("/securityhub", summary="Ingest AWS Security Hub findings")
async def ingest_securityhub(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept AWS Security Hub ASFF-format findings.

    Extracts severity label, resource ARN, account/region, compliance status
    and generator product name for downstream correlation.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "securityhub"}
    normalized = [_normalize_securityhub(e) for e in raw_events]
    _store_events(request, tenant, normalized, "aws:securityhub")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "securityhub"}


# ---------------------------------------------------------------------------
# IAM Changes
# ---------------------------------------------------------------------------

def _normalize_iam_change(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map a CloudTrail-derived IAM change event to canonical form."""
    user_identity = raw.get("userIdentity") or raw.get("UserIdentity") or {}
    return {k: v for k, v in {
        "source_kind": "iam_changes",
        "source": "iam_changes",
        "provider": "AWS",
        "ts": raw.get("eventTime") or raw.get("ts"),
        "user": (user_identity.get("userName") or user_identity.get("arn") or
                 user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName")),
        "action": raw.get("eventName"),
        "resource": raw.get("requestParameters", {}).get("userName") or raw.get("requestParameters", {}).get("roleName"),
        "event_id": raw.get("eventID"),
        "region": raw.get("awsRegion"),
        "account_id": raw.get("recipientAccountId"),
        "source_ip": raw.get("sourceIPAddress"),
        "factors": ["identity:iam_change", "cloud:access_control"],
        "risk_signals": ["privileged_change"],
        "confidence": 0.72,
        "raw": raw,
    }.items() if v is not None}


@router.post("/iam_changes", summary="Ingest AWS IAM change events")
async def ingest_iam_changes(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept AWS IAM change events (derived from CloudTrail).

    Normalises CreateUser, AttachRolePolicy, PutGroupPolicy, AssumeRole and
    similar events with elevated confidence because IAM changes are high-risk.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "iam_changes"}
    normalized = [_normalize_iam_change(e) for e in raw_events]
    _store_events(request, tenant, normalized, "aws:iam_changes")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "iam_changes"}


# ---------------------------------------------------------------------------
# S3 Access
# ---------------------------------------------------------------------------

def _normalize_s3_access(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map an S3 server-access log record to canonical form."""
    # S3 server access logs are space-delimited with a fixed schema
    if isinstance(raw, str):
        parts = raw.split()
        raw = {
            "bucket_owner": parts[0] if len(parts) > 0 else None,
            "bucket": parts[1] if len(parts) > 1 else None,
            "ts": parts[2] if len(parts) > 2 else None,
            "remote_ip": parts[3] if len(parts) > 3 else None,
            "requester": parts[4] if len(parts) > 4 else None,
            "request_id": parts[5] if len(parts) > 5 else None,
            "operation": parts[6] if len(parts) > 6 else None,
            "key": parts[7] if len(parts) > 7 else None,
            "status_code": parts[8] if len(parts) > 8 else None,
        }
    return {k: v for k, v in {
        "source_kind": "s3_access",
        "source": "s3_access",
        "provider": "AWS",
        "ts": raw.get("ts") or raw.get("time"),
        "user": raw.get("requester"),
        "ip": raw.get("remote_ip") or raw.get("remoteIP"),
        "resource": raw.get("bucket") or raw.get("Bucket"),
        "action": raw.get("operation") or raw.get("Operation"),
        "object_key": raw.get("key") or raw.get("Key"),
        "status_code": raw.get("status_code") or raw.get("httpStatus"),
        "bytes_sent": raw.get("bytes_sent") or raw.get("bytesSent"),
        "factors": ["data:s3_access"],
        "raw": raw,
    }.items() if v is not None}


@router.post("/s3_access", summary="Ingest AWS S3 access log records")
async def ingest_s3_access(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept AWS S3 access log records.

    Supports both the flat key-value dict form and the raw space-delimited
    server-access-log format.  Extracts requester, IP, bucket, object key and
    HTTP status.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "s3_access"}
    normalized = [_normalize_s3_access(e) for e in raw_events]
    _store_events(request, tenant, normalized, "aws:s3_access")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "s3_access"}


# ---------------------------------------------------------------------------
# CloudWatch
# ---------------------------------------------------------------------------

def _normalize_cloudwatch(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map a CloudWatch metric alarm or log event to canonical form."""
    is_alarm = "AlarmName" in raw or "alarmName" in raw
    if is_alarm:
        return {k: v for k, v in {
            "source_kind": "cloudwatch",
            "source": "cloudwatch",
            "provider": "AWS",
            "ts": raw.get("StateChangeTime") or raw.get("ts"),
            "title": raw.get("AlarmName") or raw.get("alarmName"),
            "action": "ALARM",
            "severity": ("high" if (raw.get("NewStateValue") or raw.get("newStateValue")) == "ALARM" else "info"),
            "resource": raw.get("AlarmArn") or raw.get("alarmArn"),
            "account_id": raw.get("AWSAccountId") or raw.get("awsAccountId"),
            "region": raw.get("Region") or raw.get("region"),
            "description": raw.get("AlarmDescription") or raw.get("alarmDescription"),
            "factors": ["cloud:cloudwatch_alarm"],
            "raw": raw,
        }.items() if v is not None}
    # Log event
    return {k: v for k, v in {
        "source_kind": "cloudwatch",
        "source": "cloudwatch",
        "provider": "AWS",
        "ts": raw.get("timestamp") or raw.get("ts"),
        "message": raw.get("message"),
        "log_group": raw.get("logGroup") or raw.get("log_group"),
        "log_stream": raw.get("logStream") or raw.get("log_stream"),
        "factors": ["cloud:cloudwatch_log"],
        "raw": raw,
    }.items() if v is not None}


@router.post("/cloudwatch", summary="Ingest AWS CloudWatch alarms and log events")
async def ingest_cloudwatch(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept AWS CloudWatch metric alarm state changes or log events.

    Alarm events are detected by the presence of ``AlarmName`` and decorated
    with elevated confidence; log events are stored for pattern correlation.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "cloudwatch"}
    normalized = [_normalize_cloudwatch(e) for e in raw_events]
    _store_events(request, tenant, normalized, "aws:cloudwatch")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "cloudwatch"}


# ---------------------------------------------------------------------------
# Config Snapshot
# ---------------------------------------------------------------------------

def _normalize_config_snapshot(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map an AWS Config resource change item to canonical form."""
    config_item = raw.get("configurationItem") or raw
    return {k: v for k, v in {
        "source_kind": "config_snapshot",
        "source": "config_snapshot",
        "provider": "AWS",
        "ts": config_item.get("configurationItemCaptureTime") or raw.get("ts"),
        "resource": config_item.get("resourceId") or config_item.get("ARN"),
        "resource_type": config_item.get("resourceType"),
        "action": config_item.get("configurationItemStatus"),
        "account_id": config_item.get("accountId"),
        "region": config_item.get("awsRegion"),
        "configuration": config_item.get("configuration"),
        "tags": config_item.get("tags"),
        "factors": ["cloud:config_change", "cloud:posture"],
        "raw": raw,
    }.items() if v is not None}


@router.post("/config_snapshot", summary="Ingest AWS Config resource change snapshots")
async def ingest_config_snapshot(
    request: Request,
    payload: Any = Body(...),
    tenant_id: Optional[str] = Header(None, alias="x-tenant-id"),
    api_key: Optional[str] = Header(None, alias="x-api-key"),
) -> Dict[str, Any]:
    """Accept AWS Config configuration change items.

    Captures resource-type, change status, account and region for posture
    correlation and compliance checks.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="missing_api_key")
    tenant = resolve_tenant_id(request, tenant_id) or tenant_id or "default"
    raw_events = _extract_events(payload)
    if not raw_events:
        return {"ok": True, "ingested": 0, "accepted": 0, "source": "config_snapshot"}
    normalized = [_normalize_config_snapshot(e) for e in raw_events]
    _store_events(request, tenant, normalized, "aws:config_snapshot")
    return {"ok": True, "ingested": len(raw_events), "accepted": len(normalized), "source": "config_snapshot"}


__all__ = ["router"]

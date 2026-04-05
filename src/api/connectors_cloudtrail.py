"""connectors_cloudtrail.py — CloudTrail log ingest endpoint.

Accepts the standard CloudTrail JSON format (``{"Records": [...]}``),
normalises each record into the canonical event shape, runs them through
the connector decision pipeline, and stores them per-tenant.

Supported payload shapes:
  * Standard exports:  ``{"Records": [{...}, ...]}``
  * Single record:     ``{eventSource, eventName, ...}``
  * Pre-normalised:    ``{"events": [{...}, ...]}``
  * Raw S3 batch:      ``[{...}, ...]``
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Header, HTTPException, Request

from src.api.runtime_state import get_server_runtime_state, persist_tenant_runtime, update_connector_health
from src.api.tenant_helpers import resolve_tenant_id

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest-cloudtrail"])

_MAX_STORED = 5_000


# ---------------------------------------------------------------------------
# CloudTrail record normalisation
# ---------------------------------------------------------------------------

_IAM_EVENTS = frozenset({
    'CreateUser', 'DeleteUser', 'AttachRolePolicy', 'DetachRolePolicy',
    'PutUserPolicy', 'DeleteUserPolicy', 'AttachUserPolicy',
    'CreateAccessKey', 'DeleteAccessKey', 'UpdateAccessKey',
    'AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity',
    'CreateRole', 'DeleteRole', 'UpdateRole',
    'CreateGroup', 'AddUserToGroup', 'RemoveUserFromGroup',
    'EnableMFADevice', 'DeactivateMFADevice',
})

_HIGH_RISK_EVENTS = frozenset({
    'StopLogging', 'DeleteTrail', 'DisableKey', 'ScheduleKeyDeletion',
    'DeleteBucket', 'PutBucketPublicAccessBlock', 'PutBucketAcl',
    'AuthorizeSecurityGroupIngress', 'CreateVpc', 'DeleteFlowLogs',
    'ModifyInstanceAttribute', 'TerminateInstances',
})


def _normalise_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Convert one CloudTrail record dict into the canonical connector event shape."""
    event_name = str(rec.get('eventName') or '')
    event_source = str(rec.get('eventSource') or '')
    error_code = rec.get('errorCode') or rec.get('error_code') or ''
    error_msg = rec.get('errorMessage') or ''
    event_time = rec.get('eventTime') or rec.get('event_ts') or ''
    account_id = rec.get('recipientAccountId') or rec.get('userIdentity', {}).get('accountId') or rec.get('account_id') or ''
    region = rec.get('awsRegion') or rec.get('region') or ''

    # Principal extraction
    uid = rec.get('userIdentity') or {}
    principal = uid.get('arn') or uid.get('userName') or uid.get('principalId') or uid.get('type') or 'unknown'
    user_type = uid.get('type') or ''

    # Source IP
    src_ip = rec.get('sourceIPAddress') or rec.get('source_ip') or ''

    # Resource ARN
    resources = rec.get('resources') or []
    resource_arn = resources[0].get('ARN') if resources and isinstance(resources[0], dict) else ''

    # Factors / risk signals
    factors: list[str] = []
    risk_signals: list[str] = []

    if event_name in _HIGH_RISK_EVENTS:
        factors.append('aws:high_risk_api')
        risk_signals.append('high_risk_api')
    if event_name in _IAM_EVENTS:
        factors.append('aws:iam_change')
        risk_signals.append('iam_change')
    if 'AssumeRole' in event_name:
        if user_type in ('AWSService', 'Unknown') or 'sts' in event_source:
            risk_signals.append('cross_account')
            factors.append('aws:cross_account_assume_role')
    if error_code in ('AccessDenied', 'UnauthorizedAccess', 'Client.UnauthorizedAccess'):
        factors.append('aws:access_denied')
        risk_signals.append('access_denied')
    if error_code:
        risk_signals.append(f'error:{error_code}')

    # Stable fingerprint for deduplication
    fp_input = f"{account_id}:{region}:{event_name}:{event_time}:{principal}"
    event_id = rec.get('eventID') or hashlib.sha256(fp_input.encode()).hexdigest()[:24]

    return {
        'id': event_id,
        'event_id': event_id,
        'source': 'cloudtrail',
        'source_kind': 'cloudtrail',
        'connector': 'cloudtrail',
        'provider': 'aws',
        'event_name': event_name,
        'event_source': event_source,
        'event_type': 'cloud_audit',
        'event_ts': event_time,
        'ts': event_time,
        'account_id': account_id,
        'region': region,
        'user': principal,
        'principal_arn': principal,
        'ip': src_ip,
        'source_ip': src_ip,
        'resource': resource_arn,
        'resource_arn': resource_arn,
        'action': event_name,
        'error_code': error_code,
        'error_message': error_msg,
        'factors': factors,
        'risk_signals': risk_signals,
        'raw': rec,
    }


def _extract_records(payload: Any) -> List[Dict[str, Any]]:
    """Extract individual CloudTrail records from any supported payload shape."""
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        # Standard CloudTrail file format
        if 'Records' in payload:
            return [r for r in (payload['Records'] or []) if isinstance(r, dict)]
        # Pre-normalised batch
        if 'events' in payload:
            return [r for r in (payload['events'] or []) if isinstance(r, dict)]
        # Single record (has eventName or eventSource)
        if 'eventName' in payload or 'eventSource' in payload:
            return [payload]
    return []


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.post('/cloudtrail')
async def ingest_cloudtrail(
    request: Request,
    payload: Any = Body(...),
    x_tenant_id: Optional[str] = Header(None, alias='x-tenant-id'),
    x_api_key: Optional[str] = Header(None, alias='x-api-key'),
) -> Dict[str, Any]:
    if not x_api_key:
        raise HTTPException(status_code=401, detail='missing_api_key')

    runtime = get_server_runtime_state(request.app)
    tenant = resolve_tenant_id(request, x_tenant_id) or x_tenant_id or 'default'

    raw_records = _extract_records(payload)
    if not raw_records:
        return {'ok': True, 'ingested': 0, 'accepted': 0, 'source': 'cloudtrail',
                'note': 'empty payload — no Records[] found'}

    # Normalise each record
    normalised = [_normalise_record(r) for r in raw_records]

    # Store in tenant runtime state
    tstate = runtime.tenants.setdefault(tenant, {})
    bucket = tstate.setdefault('recent_cloud_audit_events', [])
    bucket.extend(normalised)
    if len(bucket) > _MAX_STORED:
        del bucket[:-_MAX_STORED]

    # Emit decisions for actionable events (IAM changes, high-risk API calls, access denials)
    emitted = 0
    try:
        from src.api.routes.connectors import _emit_connector_decisions  # type: ignore
        emitted = _emit_connector_decisions('aws', 'cloudtrail', normalised)
    except Exception:
        pass

    update_connector_health(
        runtime, tenant, 'aws:cloudtrail',
        provider='aws', status='ok', ok=True,
        last_count=len(normalised),
    )
    persist_tenant_runtime(runtime, tenant)

    return {
        'ok': True,
        'ingested': len(raw_records),
        'accepted': len(normalised),
        'emitted_decisions': emitted,
        'source': 'cloudtrail',
        'tenant': tenant,
    }

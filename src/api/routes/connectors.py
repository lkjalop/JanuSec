from __future__ import annotations

from typing import Any, Dict, Iterable, Optional
import hashlib
import json
import asyncio
import os
import time

from fastapi import APIRouter, Body, Header, HTTPException, Request
from pydantic import BaseModel

from src.api.runtime_state import (
    get_server_runtime_state,
    get_connector_health,
    update_connector_health,
    persist_tenant_runtime,
    record_network_event,
)
from src.api.tenant_helpers import resolve_tenant_id
from src.connectors.aws.base import AWSConnectorConfig
from src.connectors.aws.cloudtrail import CloudTrailConnector
from src.connectors.aws.guardduty import GuardDutyConnector
from src.connectors.aws.securityhub import SecurityHubConnector
from src.connectors.aws.vpcflow import VPCFlowConnector
try:
    from src.connectors.aws.detective import DetectiveConnector
except Exception:
    DetectiveConnector = None  # type: ignore[assignment,misc]
try:
    from src.connectors.aws.macie import MacieConnector
except Exception:
    MacieConnector = None  # type: ignore[assignment,misc]
from src.connectors.azure.base import AzureConnectorConfig
from src.connectors.azure.event_hub import EventHubConnector
from src.connectors.azure.entra_id import EntraIDConnector
from src.connectors.azure.defender_cloud import DefenderCloudConnector
try:
    from src.connectors.azure.nsg_flow import NSGFlowConnector
except Exception:
    NSGFlowConnector = None  # type: ignore[assignment,misc]
try:
    from src.connectors.azure.activity_log import AzureActivityLogConnector
except Exception:
    AzureActivityLogConnector = None  # type: ignore[assignment,misc]
from src.connectors.config_store import ConnectorConfigStore
from src.connectors.resilience import RetryPolicy, execute_with_resilience, load_runtime_state
from src.integrations.polling_state import PollingStateStore
from src.core.platform_scope import scope_allows_provider
from src.core.correlation.tier1_summarizer import summarize_tier1
from src.collectors.iam_okta_adapter import OktaIAMCollector
from src.collectors.iam_sailpoint_worker import SailPointCollector
from src.connectors.mimecast import MimecastConnector
from src.connectors.proofpoint import ProofpointConnector
from src.api.connectors_email import _normalize_mimecast, _normalize_proofpoint
from src.api.iam_ingest_endpoints import _normalize_okta_identity_event

router = APIRouter(prefix="/api/v1/connectors", tags=["connectors-control"])


class ConnectorPollRequest(BaseModel):
    since_ts: Optional[Any] = None
    limit: int = 100
    region: Optional[str] = None
    log_group_name: Optional[str] = None
    dry_run: bool = False


class ConnectorConfigRequest(BaseModel):
    config: Dict[str, Any]


class LiveLaneAssessmentRequest(BaseModel):
    providers: list[str] | None = None
    connectors: list[str] | None = None
    limit_per_lane: int = 250
    auto_llm: bool = True
    include_email: bool = True


def _tenant(request: Request, tenant_id: Optional[str]) -> str:
    return resolve_tenant_id(request, tenant_id) or tenant_id or 'default'


def _test_helpers_enabled() -> bool:
    return os.getenv('TEST_HELPERS_ENABLED', '0').lower() in {'1', 'true', 'yes'}


def _enforce_scope_for_provider(provider: str) -> None:
    if not scope_allows_provider(provider):
        raise HTTPException(status_code=403, detail='provider_disabled_in_scope')


def _connector_status_payload(status: dict[str, Any] | None) -> dict[str, Any]:
    payload = dict(status or {})
    payload.setdefault('status', payload.get('status') or 'unknown')
    payload.setdefault('healthy', bool(payload.get('ok', False)))
    payload.setdefault('runtime_state', payload.get('runtime_state') or {})
    payload.setdefault('checkpoint', payload.get('checkpoint') or {})
    payload.setdefault('authenticated', bool(payload.get('authenticated', False)))
    payload.setdefault('receiving_events', bool(payload.get('receiving_events', False)))
    payload.setdefault('checkpoint_healthy', bool(payload.get('checkpoint_healthy', False)))
    payload.setdefault('beta_ready', bool(payload.get('beta_ready', False)))
    payload.setdefault('freshness', payload.get('freshness') or {})
    return payload


def _append_events(runtime, tenant: str, connector_id: str, events: list[dict[str, Any]]) -> None:
    tstate = runtime.tenants.setdefault(tenant, {})
    if connector_id in {'cloudtrail', 'guardduty', 'securityhub', 'defender_cloud'}:
        bucket = tstate.setdefault('recent_cloud_audit_events', [])
        bucket.extend(events)
        if len(bucket) > 5000:
            del bucket[:-5000]
    elif connector_id == 'vpcflow':
        bucket = tstate.setdefault('recent_network_events', [])
        bucket.extend(events)
        if len(bucket) > 5000:
            del bucket[:-5000]
        for event in events:
            record_network_event(runtime, event, tenant)
    elif connector_id in {'eventhub', 'entra_signin', 'entra_audit', 'okta', 'sailpoint'}:
        bucket = tstate.setdefault('recent_iam_events', [])
        bucket.extend(events)
        if len(bucket) > 5000:
            del bucket[:-5000]
    elif connector_id in {'mimecast', 'proofpoint'}:
        bucket = tstate.setdefault('recent_email_events', [])
        bucket.extend(events)
        if len(bucket) > 5000:
            del bucket[:-5000]


def _event_timestamp_value(event: Dict[str, Any]) -> float | None:
    for key in ('valid_time', 'event_ts', 'ts', 'timestamp', 'createdDateTime', 'activityDateTime'):
        raw = event.get(key)
        if raw in (None, '', [], {}):
            continue
        try:
            if isinstance(raw, (int, float)):
                value = float(raw)
                return value if value > 0 else None
            text = str(raw).strip()
            if not text:
                continue
            if text.endswith('Z'):
                text = text[:-1] + '+00:00'
            import datetime as _dt
            return _dt.datetime.fromisoformat(text).timestamp()
        except Exception:
            continue
    return None


def _tag_connector_events(
    events: list[dict[str, Any]],
    *,
    provider: str,
    connector: str,
    tenant: str,
) -> list[dict[str, Any]]:
    now = time.time()
    sheet_label = {
        'cloudtrail': 'CloudTrail',
        'guardduty': 'GuardDuty',
        'securityhub': 'SecurityHub',
        'vpcflow': 'VPCFlow',
        'eventhub': 'AzureEventHub',
        'entra_signin': 'EntraSignIn',
        'entra_audit': 'EntraAudit',
        'defender_cloud': 'DefenderCloud',
        'okta': 'Okta',
        'sailpoint': 'SailPoint',
        'mimecast': 'Mimecast',
        'proofpoint': 'Proofpoint',
    }.get(connector, connector)
    tagged: list[dict[str, Any]] = []
    for raw in events or []:
        if not isinstance(raw, dict):
            continue
        event = dict(raw)
        event.setdefault('tenant_id', tenant)
        event.setdefault('connector_id', f'{provider}:{connector}')
        event.setdefault('source', connector)
        event.setdefault('source_kind', connector)
        event.setdefault('sheet', sheet_label)
        valid_ts = _event_timestamp_value(event)
        if valid_ts is not None:
            event.setdefault('valid_time', valid_ts)
            event.setdefault('ts', valid_ts)
            event.setdefault('timestamp_epoch', valid_ts)
        event.setdefault('transaction_time', now)
        tagged.append(event)
    return tagged


def _runtime_events_to_assessment_rows(
    runtime,
    *,
    tenant: str,
    provider_filter: set[str],
    connector_filter: set[str],
    limit_per_lane: int,
    include_email: bool,
) -> list[dict[str, Any]]:
    tenant_state = runtime.tenants.get(tenant, {}) if runtime is not None else {}
    buckets = [
        list(tenant_state.get('recent_cloud_audit_events') or []),
        list(tenant_state.get('recent_iam_events') or []),
        list(tenant_state.get('recent_network_events') or []),
        list(tenant_state.get('recent_email_events') or []),
    ]
    rows: list[dict[str, Any]] = []
    per_lane: dict[str, int] = {}
    for bucket in buckets:
        for event in reversed(bucket):
            if not isinstance(event, dict):
                continue
            connector_id = str(event.get('connector_id') or '').strip().lower()
            provider = connector_id.split(':', 1)[0] if ':' in connector_id else str(event.get('provider') or '').strip().lower()
            connector = connector_id.split(':', 1)[1] if ':' in connector_id else str(event.get('source_kind') or event.get('source') or '').strip().lower()
            if connector in {'mimecast', 'proofpoint'} and not include_email:
                continue
            if provider_filter and provider not in provider_filter:
                continue
            if connector_filter and connector not in connector_filter:
                continue
            if per_lane.get(connector_id, 0) >= limit_per_lane:
                continue
            row = dict(event)
            row['row_index'] = len(rows)
            row.setdefault('fingerprint', row.get('id') or row.get('event_id') or f'{connector_id}:{per_lane.get(connector_id, 0)}')
            row.setdefault('source_file', f'{connector or "live"}.json')
            row.setdefault('description', row.get('description') or row.get('reason') or row.get('subject') or row.get('action') or row.get('event_type') or 'Live connector evidence')
            row.setdefault('export_source', connector or provider or 'live')
            row.setdefault('provider_profile', provider or 'generic')
            row.setdefault('intake_mode', 'live')
            row.setdefault('review_state', 'needs_investigation')
            rows.append(row)
            per_lane[connector_id] = per_lane.get(connector_id, 0) + 1
    return rows


def _build_live_lane_assessment(
    *,
    request: Request,
    tenant: str,
    providers: list[str] | None,
    connectors: list[str] | None,
    limit_per_lane: int,
    auto_llm: bool,
    include_email: bool,
) -> dict[str, Any]:
    runtime = get_server_runtime_state(request.app)
    provider_filter = {str(item).strip().lower() for item in (providers or []) if str(item).strip()}
    connector_filter = {str(item).strip().lower() for item in (connectors or []) if str(item).strip()}
    rows = _runtime_events_to_assessment_rows(
        runtime,
        tenant=tenant,
        provider_filter=provider_filter,
        connector_filter=connector_filter,
        limit_per_lane=max(1, int(limit_per_lane or 250)),
        include_email=include_email,
    )
    if not rows:
        raise HTTPException(status_code=404, detail='no_live_connector_events')
    from src.analysis.offline_workbook_assessment import build_offline_workbook_assessment
    from src.api.deep_analyze_endpoints import _hydrate_assessment_semantics, _persist_assessment_state
    assessment_id = f'live-lane-{tenant}-{hashlib.sha256(str(time.time()).encode("utf-8")).hexdigest()[:8]}'
    assessment = build_offline_workbook_assessment(rows, assessment_id=assessment_id, org=tenant, auto_llm=auto_llm)
    assessment['live_lane'] = {
        'providers': sorted(provider_filter) or ['aws', 'azure', 'okta', 'sailpoint', 'email'],
        'connectors': sorted(connector_filter),
        'generated_from_runtime': True,
    }
    assessment['connector_health_snapshot'] = get_connector_health(runtime, tenant)
    assessment['intake_mode'] = 'live'
    assessment['provider_profile'] = 'multi_cloud'
    assessment = _hydrate_assessment_semantics(assessment)
    _persist_assessment_state(assessment_id, assessment)
    return assessment


def _event_fingerprint(event: Dict[str, Any]) -> str:
    try:
        stable = event.get('id') or json.dumps(event, sort_keys=True, separators=(',', ':'), default=str)
        return hashlib.sha256(str(stable).encode('utf-8')).hexdigest()
    except Exception:
        return str(event.get('id') or time.time())


def _dedupe_events(runtime, tenant: str, provider: str, connector: str, events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    tstate = runtime.tenants.setdefault(tenant, {})
    key = f'connector_recent_ids:{provider}:{connector}'
    recent: list[str] = tstate.setdefault(key, [])
    seen = set(recent)
    filtered: list[dict[str, Any]] = []
    duplicate_count = 0
    for event in events:
        fp = _event_fingerprint(event)
        if fp in seen:
            duplicate_count += 1
            continue
        filtered.append(event)
        recent.append(fp)
        seen.add(fp)
    if len(recent) > 2000:
        del recent[:-2000]
    return filtered, duplicate_count


def _coerce_since_ts(value: Any, default_seconds: int = 300) -> float:
    try:
        if value is None:
            raise ValueError
        return float(value)
    except Exception:
        return time.time() - default_seconds


def _aws_decision_inputs(connector: str, event: Dict[str, Any]) -> tuple[str, str, float, list[str], dict[str, Any]] | None:
    """Map normalised AWS connector events to (event_id, verdict, confidence, factors, meta).

    Returns None for low-risk/informational events that should not emit decisions.
    """
    source = str(event.get('source') or connector)
    event_id = str(
        event.get('id')
        or event.get('event_id')
        or f"{source}:{event.get('event_ts') or event.get('ts') or time.time()}:{event.get('user') or event.get('resource') or event.get('account_id') or 'entity'}"
    )
    factors: list[str] = list(event.get('factors') or [])
    risk_signals: list[str] = [str(s) for s in (event.get('risk_signals') or []) if s]
    verdict = 'allow'
    confidence = 0.35

    if connector == 'guardduty':
        sev = float(event.get('severity') or 0)
        if sev >= 7.0:
            verdict = 'bad'
            confidence = min(0.5 + sev / 20.0, 0.97)
            factors.extend(['aws:guardduty_high'])
        elif sev >= 4.0:
            verdict = 'suspicious'
            confidence = 0.65
            factors.extend(['aws:guardduty_medium'])
        else:
            return None  # low severity — skip
    elif connector == 'securityhub':
        sev = str(event.get('severity') or '').upper()
        if sev in {'CRITICAL', 'HIGH'}:
            verdict = 'bad' if sev == 'CRITICAL' else 'suspicious'
            confidence = 0.9 if sev == 'CRITICAL' else 0.82
            factors.extend([f'aws:securityhub_{sev.lower()}'])
        elif sev == 'MEDIUM':
            verdict = 'suspicious'
            confidence = 0.65
            factors.extend(['aws:securityhub_medium'])
        else:
            return None
    elif connector == 'cloudtrail':
        # IAM, privilege-change, or error events
        event_name = str(event.get('event_name') or event.get('action') or '')
        error_code = event.get('error_code') or ''
        if 'CreateUser' in event_name or 'AttachRolePolicy' in event_name or 'PutUserPolicy' in event_name or 'CreateAccessKey' in event_name:
            verdict = 'suspicious'
            confidence = 0.75
            factors.extend(['aws:iam_privilege_change'])
        elif error_code in ('AccessDenied', 'UnauthorizedAccess'):
            verdict = 'suspicious'
            confidence = 0.6
            factors.extend(['aws:access_denied'])
        elif 'AssumeRole' in event_name and any(s in risk_signals for s in ('cross_account', 'external_principal')):
            verdict = 'suspicious'
            confidence = 0.72
            factors.extend(['aws:cross_account_assume_role'])
        else:
            return None
    elif connector == 'vpcflow':
        action = str(event.get('action') or '').upper()
        if action == 'REJECT' and any(s in risk_signals for s in ('scan', 'external_ip', 'port_sweep')):
            verdict = 'suspicious'
            confidence = 0.6
            factors.extend(['aws:vpcflow_reject_scan'])
        else:
            return None
    elif connector in ('s3_access', 'cloudwatch', 'config_snapshot'):
        if 'public_access' in risk_signals or 'exposed_bucket' in risk_signals:
            verdict = 'suspicious'
            confidence = 0.7
            factors.extend(['aws:public_exposure'])
        else:
            return None
    else:
        # Generic fallback: require pre-set factors
        if not factors:
            return None
        verdict = 'suspicious'
        confidence = 0.6

    factors = sorted({str(f) for f in factors if f})
    if not factors:
        return None
    meta = {
        'details': {
            'source': source,
            'event_type': event.get('event_type') or event.get('event_name'),
            'user': event.get('user') or event.get('principal_arn'),
            'ip': event.get('ip') or event.get('source_ip'),
            'resource': event.get('resource') or event.get('resource_arn'),
            'action': event.get('action') or event.get('event_name'),
            'account_id': event.get('account_id'),
            'region': event.get('region'),
        },
        'hopgraph_context': {
            'provider': 'aws',
            'source': source,
            'event_type': event.get('event_type') or event.get('event_name'),
            'event_ts': event.get('event_ts') or event.get('ts'),
            'user': event.get('user') or event.get('principal_arn'),
            'ip': event.get('ip') or event.get('source_ip'),
            'resource': event.get('resource') or event.get('resource_arn'),
            'action': event.get('action') or event.get('event_name'),
            'account_id': event.get('account_id'),
            'risk_signals': risk_signals,
        },
        'recommendation_actions': [
            {
                'id': f'aws|review|{connector}',
                'domain': 'aws',
                'action': 'review_evidence',
                'priority': 'high' if verdict == 'bad' else 'medium',
                'status': 'pending',
                'updated_ts': time.time(),
            }
        ],
    }
    return event_id, verdict, confidence, factors, meta


def _azure_decision_inputs(connector: str, event: Dict[str, Any]) -> tuple[str, str, float, list[str], dict[str, Any]] | None:
    source = str(event.get('source') or connector)
    event_id = str(
        event.get('id')
        or event.get('event_id')
        or f"{source}:{event.get('event_ts') or event.get('ts') or time.time()}:{event.get('user') or event.get('resource') or 'entity'}"
    )
    factors = list(event.get('factors') or [])
    risk_signals = [str(s) for s in (event.get('risk_signals') or []) if s]
    verdict = 'allow'
    confidence = 0.35

    if connector == 'entra_signin':
        if any(sig.startswith('risk:') for sig in risk_signals) or 'signin_failure' in risk_signals:
            verdict = 'suspicious'
            confidence = 0.72
            factors.extend(['iam:signin_risk'])
    elif connector == 'entra_audit':
        if 'privilege_change' in risk_signals:
            verdict = 'suspicious'
            confidence = 0.78
            factors.extend(['iam:privilege_change'])
    elif connector == 'defender_cloud':
        sev = str(event.get('severity') or '').lower()
        if sev in {'high', 'critical'}:
            verdict = 'bad'
            confidence = 0.9 if sev == 'critical' else 0.84
            factors.extend(['cloud:defender_finding'])
        elif sev:
            verdict = 'suspicious'
            confidence = 0.7
            factors.extend(['cloud:defender_finding'])
    elif connector == 'nsg_flow':
        action = str(event.get('action') or event.get('flow_state') or '').upper()
        if action in ('D', 'DENY', 'REJECTED') and any(
            s in (event.get('risk_signals') or []) for s in ('scan', 'external_ip', 'port_sweep')
        ):
            verdict = 'suspicious'
            confidence = 0.62
            factors.extend(['azure:nsg_denied_scan'])
        elif action in ('D', 'DENY', 'REJECTED'):
            verdict = 'suspicious'
            confidence = 0.5
            factors.extend(['azure:nsg_flow_deny'])
        else:
            return None
    elif connector == 'azure_activity':
        operation = str(event.get('operation_name') or event.get('action') or '')
        status = str(event.get('status') or event.get('result') or '').lower()
        if 'delete' in operation.lower() or 'write' in operation.lower():
            if status in ('failed', 'failure'):
                verdict = 'suspicious'
                confidence = 0.6
                factors.extend(['azure:activity_write_failure'])
            elif any(kw in operation.lower() for kw in ('roledefinitions', 'roleassignments', 'locks', 'policy')):
                verdict = 'suspicious'
                confidence = 0.7
                factors.extend(['azure:activity_privileged_op'])
            else:
                return None
        else:
            return None

    factors = sorted({str(f) for f in factors if f})
    if not factors:
        return None
    meta = {
        'details': {
            'source': source,
            'event_type': event.get('event_type'),
            'user': event.get('user'),
            'ip': event.get('ip'),
            'resource': event.get('resource'),
            'action': event.get('action'),
        },
        'hopgraph_context': {
            'provider': 'azure',
            'source': source,
            'event_type': event.get('event_type'),
            'event_ts': event.get('event_ts') or event.get('ts'),
            'user': event.get('user'),
            'ip': event.get('ip'),
            'resource': event.get('resource'),
            'action': event.get('action'),
            'risk_signals': risk_signals,
        },
        'recommendation_actions': [
            {
                'id': f'azure|review|{connector}',
                'domain': 'azure',
                'action': 'review_evidence',
                'priority': 'high' if verdict == 'bad' else 'medium',
                'status': 'pending',
                'updated_ts': time.time(),
            }
        ],
    }
    if verdict == 'allow':
        return None
    return event_id, verdict, confidence, factors, meta


def _emit_connector_decisions(provider: str, connector: str, events: list[dict[str, Any]]) -> int:
    emitted = 0
    try:
        from src.api.server import _record_decision  # type: ignore
    except Exception:
        return 0
    for event in events[:200]:
        try:
            if provider == 'azure':
                decision_inputs = _azure_decision_inputs(connector, event)
            elif provider == 'aws':
                decision_inputs = _aws_decision_inputs(connector, event)
            else:
                decision_inputs = _generic_decision_inputs(provider, connector, event)
            if not decision_inputs:
                continue
            event_id, verdict, confidence, factors, meta = decision_inputs
            event_for_t1 = dict(event)
            event_for_t1['event_id'] = event_id
            event_for_t1['verdict'] = verdict.upper()
            event_for_t1['confidence'] = confidence
            event_for_t1['factors'] = [
                {'name': factor, 'score': confidence}
                for factor in factors
            ]
            details = (meta or {}).get('details') or {}
            event_for_t1['correlation_emission'] = {
                'rule': f'connector:{connector}',
                'computed_score': confidence,
                'verdict': verdict.upper(),
                'mitre': list(event.get('mitre') or []),
                'evidence': {
                    'source': details.get('source') or connector,
                    'event_type': details.get('event_type'),
                    'user': details.get('user'),
                    'ip': details.get('ip'),
                    'resource': details.get('resource'),
                    'action': details.get('action'),
                },
            }
            tier1_summary = summarize_tier1(event_for_t1)
            meta = dict(meta or {})
            meta['llm_summaries'] = {
                **(meta.get('llm_summaries') or {}),
                'tier1': tier1_summary,
                'source': 'deterministic_connector',
            }
            _record_decision(event_id, verdict, confidence, factors, meta)
            emitted += 1
        except Exception:
            continue
    return emitted


def _generic_decision_inputs(provider: str, connector: str, event: Dict[str, Any]) -> tuple[str, str, float, list[str], dict[str, Any]] | None:
    source = str(event.get('source') or connector or provider)
    event_id = str(event.get('id') or event.get('event_id') or f"{provider}:{connector}:{event.get('ts') or time.time()}")
    factors = sorted({str(f) for f in (event.get('factors') or []) if f})
    severity = str(event.get('severity') or '').lower()
    verdict = 'allow'
    confidence = 0.35
    if provider in {'okta', 'sailpoint'}:
        action = str(event.get('action') or event.get('event_type') or '').lower()
        result = str(event.get('result') or '').lower()
        if 'factor' in action or 'privilege' in action or 'policy' in action:
            verdict = 'suspicious'
            confidence = 0.76
            factors.extend(['iam:privilege_change'])
        elif any(token in action for token in ('login', 'signin', 'auth')) and result not in {'success', 'allow', ''}:
            verdict = 'suspicious'
            confidence = 0.68
            factors.extend(['iam:signin_risk'])
    elif provider == 'email':
        if severity in {'critical', 'high'}:
            verdict = 'bad'
            confidence = 0.86 if severity == 'critical' else 0.78
        elif factors:
            verdict = 'suspicious'
            confidence = 0.66
    factors = sorted({str(f) for f in factors if f})
    if verdict == 'allow' or not factors:
        return None
    return (
        event_id,
        verdict,
        confidence,
        factors,
        {
            'details': {
                'source': source,
                'event_type': event.get('event_type') or event.get('action'),
                'user': event.get('user') or event.get('actor'),
                'ip': event.get('ip'),
                'resource': event.get('resource') or event.get('target'),
                'action': event.get('action') or event.get('event_type'),
            },
            'hopgraph_context': {
                'provider': provider,
                'source': source,
                'event_type': event.get('event_type') or event.get('action'),
                'event_ts': event.get('event_ts') or event.get('ts'),
                'user': event.get('user') or event.get('actor'),
                'ip': event.get('ip'),
                'resource': event.get('resource') or event.get('target'),
                'action': event.get('action') or event.get('event_type'),
            },
            'recommendation_actions': [
                {
                    'id': f'{provider}|review|{connector}',
                    'domain': provider,
                    'action': 'review_evidence',
                    'priority': 'high' if verdict == 'bad' else 'medium',
                    'status': 'pending',
                    'updated_ts': time.time(),
                }
            ],
        },
    )


def _aws_connector(name: str, body: ConnectorPollRequest):
    cfg = AWSConnectorConfig(region=body.region, log_group_name=body.log_group_name)
    if name == 'cloudtrail':
        conn = CloudTrailConnector(cfg)
        fetcher = lambda: list(conn.fetch_events(start_time=body.since_ts))
    elif name == 'guardduty':
        conn = GuardDutyConnector(cfg)
        fetcher = lambda: list(conn.fetch_findings())
    elif name == 'securityhub':
        conn = SecurityHubConnector(cfg)
        fetcher = lambda: list(conn.fetch_findings())
    elif name == 'vpcflow':
        conn = VPCFlowConnector(cfg)
        fetcher = lambda: list(conn.fetch_records())
    elif name == 'detective':
        if DetectiveConnector is None:
            raise HTTPException(status_code=503, detail='detective_connector_unavailable')
        conn = DetectiveConnector(cfg)
        fetcher = lambda: list(conn.fetch_findings_groups())
    elif name == 'macie':
        if MacieConnector is None:
            raise HTTPException(status_code=503, detail='macie_connector_unavailable')
        conn = MacieConnector(cfg)
        fetcher = lambda: list(conn.fetch_findings())
    else:
        raise HTTPException(status_code=404, detail='unknown_connector')
    return conn, fetcher


def _azure_connector(name: str, body: ConnectorPollRequest, tenant: str):
    cfg_store = ConnectorConfigStore()
    stored_cfg = cfg_store.load(tenant, 'azure', name)
    cfg = AzureConnectorConfig.from_mapping({'tenant_id': tenant, **stored_cfg})
    if body.log_group_name:
        stored_cfg['log_group_name'] = body.log_group_name
    if name == 'eventhub':
        conn = EventHubConnector(cfg)
        fetcher = lambda: list(conn.fetch_events(limit=body.limit))
    elif name == 'entra_signin':
        conn = EntraIDConnector(cfg)
        fetcher = lambda: list(conn.fetch_signins(body.since_ts))
    elif name == 'entra_audit':
        conn = EntraIDConnector(cfg)
        fetcher = lambda: list(conn.fetch_audits(body.since_ts))
    elif name == 'defender_cloud':
        conn = DefenderCloudConnector(cfg)
        fetcher = lambda: list(conn.fetch_findings(body.since_ts))
    elif name == 'nsg_flow':
        if NSGFlowConnector is None:
            raise HTTPException(status_code=503, detail='nsg_flow_connector_unavailable')
        conn = NSGFlowConnector(cfg)
        fetcher = lambda: list(conn.fetch_flows())
    elif name == 'azure_activity':
        if AzureActivityLogConnector is None:
            raise HTTPException(status_code=503, detail='azure_activity_connector_unavailable')
        conn = AzureActivityLogConnector(cfg)
        fetcher = lambda: list(conn.fetch_events())
    else:
        raise HTTPException(status_code=404, detail='unknown_connector')
    return conn, fetcher


def _okta_connector(name: str, body: ConnectorPollRequest, tenant: str):
    if name != 'okta':
        raise HTTPException(status_code=404, detail='unknown_connector')
    store = ConnectorConfigStore()
    cfg = store.load(tenant, 'okta', name)
    if cfg.get('org_url'):
        os.environ['OKTA_ORG_URL'] = str(cfg.get('org_url'))
    if cfg.get('api_token'):
        os.environ['OKTA_API_TOKEN'] = str(cfg.get('api_token'))
    conn = OktaIAMCollector(tenant_id=tenant)
    fetcher = lambda: [
        _normalize_okta_identity_event(evt, tenant)
        for evt in (conn.fetch_events(_coerce_since_ts(body.since_ts)) or [])
        if isinstance(evt, dict)
    ]
    return conn, fetcher


def _sailpoint_connector(name: str, body: ConnectorPollRequest, tenant: str):
    if name not in {'sailpoint', 'identitynow'}:
        raise HTTPException(status_code=404, detail='unknown_connector')
    store = ConnectorConfigStore()
    cfg = store.load(tenant, 'sailpoint', 'sailpoint')
    conn = SailPointCollector(
        tenant_id=tenant,
        base_url=cfg.get('base_url'),
        client_id=cfg.get('client_id'),
        client_secret=cfg.get('client_secret'),
    )
    fetcher = lambda: [_ingest_generic_identity_normalized(evt, tenant, 'sailpoint') for evt in (asyncio.run(conn.poll_events()) or []) if isinstance(evt, dict)]
    return conn, fetcher


def _ingest_generic_identity_normalized(raw: Dict[str, Any], tenant: str, provider: str) -> Dict[str, Any]:
    payload = {'events': [raw], 'tenant_id': tenant}
    # reuse existing generic mapping semantics from iam ingest path
    tenant_value, _ = tenant, 1
    return {
        'id': raw.get('id') or raw.get('event_id') or raw.get('raw', {}).get('id'),
        'tenant_id': tenant_value,
        'provider': provider,
        'domain': 'identity',
        'ts': raw.get('timestamp') or raw.get('ts'),
        'actor': raw.get('actor'),
        'action': raw.get('eventType') or raw.get('operation'),
        'ip': raw.get('ip'),
        'result': raw.get('result'),
        'target': raw.get('target'),
        'severity': 'high' if 'privilege' in str(raw.get('operation') or '').lower() else 'medium',
        'factors': ['iam:connector_ingest'] + (['iam:privilege_change'] if 'privilege' in str(raw.get('operation') or '').lower() else []),
        'raw': raw,
    }


def _email_connector(name: str, body: ConnectorPollRequest, tenant: str):
    store = ConnectorConfigStore()
    cfg = store.load(tenant, 'email', name)
    if name == 'mimecast':
        conn = MimecastConnector()
        if cfg.get('client_id'):
            os.environ['MIMECAST_CLIENT_ID'] = str(cfg.get('client_id'))
        if cfg.get('client_secret'):
            os.environ['MIMECAST_CLIENT_SECRET'] = str(cfg.get('client_secret'))
        if cfg.get('token_url'):
            os.environ['MIMECAST_TOKEN_URL'] = str(cfg.get('token_url'))
        fetcher = lambda: [_normalize_mimecast(evt) for evt in ((asyncio.run(conn.execute('email', tenant, None)) or {}).get('events') or []) if isinstance(evt, dict)]
    elif name == 'proofpoint':
        conn = ProofpointConnector()
        if cfg.get('client_id'):
            os.environ['PROOFPOINT_CLIENT_ID'] = str(cfg.get('client_id'))
        if cfg.get('client_secret'):
            os.environ['PROOFPOINT_CLIENT_SECRET'] = str(cfg.get('client_secret'))
        if cfg.get('token_url'):
            os.environ['PROOFPOINT_TOKEN_URL'] = str(cfg.get('token_url'))
        fetcher = lambda: [_normalize_proofpoint(evt) for evt in ((asyncio.run(conn.execute('email', tenant, None)) or {}).get('events') or []) if isinstance(evt, dict)]
    else:
        raise HTTPException(status_code=404, detail='unknown_connector')
    return conn, fetcher


def _connector_config_payload(provider: str, connector: str, tenant: str) -> Dict[str, Any]:
    store = ConnectorConfigStore()
    if provider == 'azure':
        cfg = AzureConnectorConfig.from_mapping({'tenant_id': tenant, **store.load(tenant, provider, connector)})
        return cfg.redacted()
    payload = store.load(tenant, provider, connector)
    if provider in {'okta', 'sailpoint', 'email'}:
        redacted = dict(payload or {})
        for key in ('api_token', 'client_secret', 'api_secret', 'access_token'):
            if redacted.get(key):
                redacted[key] = '***'
        return redacted
    return payload


@router.get('/{tenant_id}/{provider}/{connector}/config')
def connector_config(
    tenant_id: str,
    provider: str,
    connector: str,
    request: Request,
    api_key: Optional[str] = Header(None, alias='x-api-key'),
) -> Dict[str, Any]:
    if not api_key:
        raise HTTPException(status_code=401, detail='missing_api_key')
    _enforce_scope_for_provider(provider)
    tenant = _tenant(request, tenant_id)
    return {'tenant': tenant, 'provider': provider, 'connector': connector, 'config': _connector_config_payload(provider, connector, tenant)}


@router.put('/{tenant_id}/{provider}/{connector}/config')
def connector_config_put(
    tenant_id: str,
    provider: str,
    connector: str,
    request: Request,
    body: ConnectorConfigRequest,
    api_key: Optional[str] = Header(None, alias='x-api-key'),
) -> Dict[str, Any]:
    if not api_key:
        raise HTTPException(status_code=401, detail='missing_api_key')
    _enforce_scope_for_provider(provider)
    tenant = _tenant(request, tenant_id)
    store = ConnectorConfigStore()
    payload = dict(body.config or {})
    if _test_helpers_enabled() and isinstance(payload.get('fixture_events'), list):
        store.save(tenant, provider, connector, payload)
        return {'ok': True, 'tenant': tenant, 'provider': provider, 'connector': connector, 'config': _connector_config_payload(provider, connector, tenant)}
    if provider == 'azure':
        cfg = AzureConnectorConfig.from_mapping({'tenant_id': tenant, **payload})
        missing = cfg.validate_for(connector)
        if missing:
            raise HTTPException(status_code=400, detail={'missing': missing})
        store.save(tenant, provider, connector, payload)
        return {'ok': True, 'tenant': tenant, 'provider': provider, 'connector': connector, 'config': cfg.redacted()}
    if provider == 'okta':
        missing = [key for key in ('org_url', 'api_token') if not payload.get(key)]
        if missing:
            raise HTTPException(status_code=400, detail={'missing': missing})
    elif provider == 'sailpoint':
        missing = [key for key in ('base_url', 'client_id', 'client_secret') if not payload.get(key)]
        if missing:
            raise HTTPException(status_code=400, detail={'missing': missing})
    elif provider == 'email':
        if connector == 'mimecast':
            missing = [key for key in ('client_id', 'client_secret', 'token_url') if not payload.get(key)]
        elif connector == 'proofpoint':
            missing = [key for key in ('client_id', 'client_secret', 'token_url') if not payload.get(key)]
        else:
            raise HTTPException(status_code=404, detail='unknown_connector')
        if missing:
            raise HTTPException(status_code=400, detail={'missing': missing})
    store.save(tenant, provider, connector, payload)
    return {'ok': True, 'tenant': tenant, 'provider': provider, 'connector': connector, 'config': _connector_config_payload(provider, connector, tenant)}


@router.get('/{tenant_id}/status')
def list_connector_status(
    tenant_id: str,
    request: Request,
    api_key: Optional[str] = Header(None, alias='x-api-key'),
) -> Dict[str, Any]:
    if not api_key:
        raise HTTPException(status_code=401, detail='missing_api_key')
    tenant = _tenant(request, tenant_id)
    runtime = get_server_runtime_state(request.app)
    return {'tenant': tenant, 'connectors': get_connector_health(runtime, tenant)}


@router.get('/{tenant_id}/{provider}/{connector}/status')
def connector_status(
    tenant_id: str,
    provider: str,
    connector: str,
    request: Request,
    api_key: Optional[str] = Header(None, alias='x-api-key'),
) -> Dict[str, Any]:
    if not api_key:
        raise HTTPException(status_code=401, detail='missing_api_key')
    _enforce_scope_for_provider(provider)
    tenant = _tenant(request, tenant_id)
    runtime = get_server_runtime_state(request.app)
    connector_id = f'{provider}:{connector}'
    return {'tenant': tenant, 'provider': provider, 'connector': connector, 'status': _connector_status_payload(get_connector_health(runtime, tenant, connector_id))}


@router.get('/{tenant_id}/{provider}/{connector}/checkpoint')
def connector_checkpoint(
    tenant_id: str,
    provider: str,
    connector: str,
    request: Request,
    api_key: Optional[str] = Header(None, alias='x-api-key'),
) -> Dict[str, Any]:
    if not api_key:
        raise HTTPException(status_code=401, detail='missing_api_key')
    _enforce_scope_for_provider(provider)
    tenant = _tenant(request, tenant_id)
    runtime = get_server_runtime_state(request.app)
    connector_id = f'{provider}:{connector}'
    status = get_connector_health(runtime, tenant, connector_id)
    return {'tenant': tenant, 'provider': provider, 'connector': connector, 'checkpoint': status.get('checkpoint') or {}}


@router.post('/{tenant_id}/{provider}/{connector}/poll')
def connector_poll(
    tenant_id: str,
    provider: str,
    connector: str,
    request: Request,
    body: ConnectorPollRequest = Body(default=ConnectorPollRequest()),
    api_key: Optional[str] = Header(None, alias='x-api-key'),
) -> Dict[str, Any]:
    if not api_key:
        raise HTTPException(status_code=401, detail='missing_api_key')
    _enforce_scope_for_provider(provider)
    tenant = _tenant(request, tenant_id)
    runtime = get_server_runtime_state(request.app)
    connector_id = f'{provider}:{connector}'
    state_store = PollingStateStore()
    try:
        stored_payload = ConnectorConfigStore().load(tenant, provider, connector)
        if _test_helpers_enabled() and isinstance(stored_payload.get('fixture_events'), list) and not body.dry_run:
            runtime_state = load_runtime_state(state_store, tenant, provider, connector)
            raw_events = list(stored_payload.get('fixture_events') or [])[: max(0, int(body.limit or 0))]
            events = _tag_connector_events(raw_events, provider=provider, connector=connector, tenant=tenant)
            events, duplicate_count = _dedupe_events(runtime, tenant, provider, connector, events)
            _append_events(runtime, tenant, connector, events)
            emitted_decisions = _emit_connector_decisions(provider, connector, events)
            checkpoint = {
                'fixture_cursor': (events[-1].get('valid_time') or events[-1].get('ts')) if events else runtime_state.get('fixture_cursor'),
                'fixture_count': int(runtime_state.get('fixture_count') or 0) + len(events),
            }
            runtime_state.update({
                'last_error': None,
                'last_success_ts': time.time(),
                'last_latency_ms': 0,
                'last_duplicate_count': duplicate_count,
                'fixture_cursor': checkpoint.get('fixture_cursor'),
                'fixture_count': checkpoint.get('fixture_count'),
                # Reset circuit breaker state in fixture mode so prior
                # real-connector failures don't block fixture validation.
                'circuit_open_until': 0,
                'consecutive_failures': 0,
            })
            update_connector_health(
                runtime,
                tenant,
                connector_id,
                provider=provider,
                status='ok',
                ok=True,
                last_count=len(events),
                checkpoint=checkpoint,
                runtime_state=runtime_state,
                authenticated=True,
                receiving_events=bool(events),
                checkpoint_healthy=True,
                beta_ready=bool(events),
                freshness={'heartbeat_stale': False, 'last_poll_ts': time.time()},
            )
            runtime.tenants.setdefault(tenant, {}).setdefault('connector_health', {}).setdefault(connector_id, {})['last_duplicate_count'] = duplicate_count
            runtime.tenants.setdefault(tenant, {}).setdefault('connector_health', {}).setdefault(connector_id, {})['last_latency_ms'] = 0
            persist_tenant_runtime(runtime, tenant)
            return {
                'ok': True,
                'tenant': tenant,
                'provider': provider,
                'connector': connector,
                'ingested': len(events),
                'decisions_emitted': emitted_decisions,
                'duplicates_suppressed': duplicate_count,
                'checkpoint': checkpoint,
                'runtime_state': runtime_state,
            }
        if provider == 'aws':
            conn, fetcher = _aws_connector(connector, body)
        elif provider == 'azure':
            conn, fetcher = _azure_connector(connector, body, tenant)
        elif provider == 'okta':
            conn, fetcher = _okta_connector(connector, body, tenant)
        elif provider == 'sailpoint':
            conn, fetcher = _sailpoint_connector(connector, body, tenant)
        elif provider == 'email':
            conn, fetcher = _email_connector(connector, body, tenant)
        else:
            raise HTTPException(status_code=404, detail='unknown_provider')
        if provider == 'azure':
            cfg = conn.cfg
            missing = cfg.validate_for(connector)
            if missing and not body.dry_run:
                update_connector_health(
                    runtime,
                    tenant,
                    connector_id,
                    provider=provider,
                    status='misconfigured',
                    ok=False,
                    error=','.join(missing),
                    authenticated=False,
                    receiving_events=False,
                    checkpoint_healthy=False,
                )
                persist_tenant_runtime(runtime, tenant)
                raise HTTPException(status_code=400, detail={'missing': missing})
        if provider in {'okta', 'sailpoint', 'email'} and not body.dry_run:
            missing = []
            stored_payload = ConnectorConfigStore().load(tenant, provider, connector)
            if provider == 'okta':
                missing = [key for key in ('org_url', 'api_token') if not stored_payload.get(key)]
            elif provider == 'sailpoint':
                missing = [key for key in ('base_url', 'client_id', 'client_secret') if not stored_payload.get(key)]
            elif provider == 'email':
                missing = [key for key in ('client_id', 'client_secret', 'token_url') if not stored_payload.get(key)]
            if missing:
                update_connector_health(
                    runtime,
                    tenant,
                    connector_id,
                    provider=provider,
                    status='misconfigured',
                    ok=False,
                    error=','.join(missing),
                    authenticated=False,
                    receiving_events=False,
                    checkpoint_healthy=False,
                )
                persist_tenant_runtime(runtime, tenant)
                raise HTTPException(status_code=400, detail={'missing': missing})
        if body.dry_run:
            runtime_state = load_runtime_state(state_store, tenant, provider, connector)
            checkpoint = getattr(conn, 'ck', {})
            update_connector_health(
                runtime,
                tenant,
                connector_id,
                provider=provider,
                status='dry_run',
                ok=True,
                checkpoint=checkpoint,
                error=runtime_state.get('last_error'),
                authenticated=True,
                receiving_events=False,
                checkpoint_healthy=bool(checkpoint),
            )
            persist_tenant_runtime(runtime, tenant)
            return {
                'ok': True,
                'tenant': tenant,
                'provider': provider,
                'connector': connector,
                'dry_run': True,
                'checkpoint': getattr(conn, 'ck', {}),
                'runtime_state': runtime_state,
            }
        events = execute_with_resilience(
            lambda: fetcher() or [],
            store=state_store,
            tenant_id=tenant,
            provider=provider,
            connector=connector,
            policy=RetryPolicy(),
        )
        events = _tag_connector_events(events, provider=provider, connector=connector, tenant=tenant)
        events, duplicate_count = _dedupe_events(runtime, tenant, provider, connector, events)
        _append_events(runtime, tenant, connector, events)
        emitted_decisions = _emit_connector_decisions(provider, connector, events)
        runtime_state = load_runtime_state(state_store, tenant, provider, connector)
        update_connector_health(
            runtime,
            tenant,
            connector_id,
            provider=provider,
            status='ok',
            ok=True,
            last_count=len(events),
            checkpoint=getattr(conn, 'ck', {}),
            error=runtime_state.get('last_error'),
            authenticated=True,
            receiving_events=bool(events),
            checkpoint_healthy=bool(getattr(conn, 'ck', {})),
        )
        runtime.tenants.setdefault(tenant, {}).setdefault('connector_health', {}).setdefault(connector_id, {})['last_duplicate_count'] = duplicate_count
        runtime.tenants.setdefault(tenant, {}).setdefault('connector_health', {}).setdefault(connector_id, {})['last_latency_ms'] = runtime_state.get('last_latency_ms')
        persist_tenant_runtime(runtime, tenant)
        return {
            'ok': True,
            'tenant': tenant,
            'provider': provider,
            'connector': connector,
            'ingested': len(events),
            'decisions_emitted': emitted_decisions,
            'duplicates_suppressed': duplicate_count,
            'checkpoint': getattr(conn, 'ck', {}),
            'runtime_state': runtime_state,
        }
    except HTTPException:
        raise
    except Exception as exc:
        runtime_state = load_runtime_state(state_store, tenant, provider, connector)
        update_connector_health(
            runtime,
            tenant,
            connector_id,
            provider=provider,
            status='error',
            ok=False,
            error=str(exc),
            checkpoint=getattr(locals().get('conn', None), 'ck', {}),
            authenticated=False,
            receiving_events=False,
            checkpoint_healthy=False,
        )
        runtime.tenants.setdefault(tenant, {}).setdefault('connector_health', {}).setdefault(connector_id, {})['runtime_state'] = runtime_state
        persist_tenant_runtime(runtime, tenant)
        raise HTTPException(status_code=502, detail=f'connector_poll_failed:{connector}')


@router.post('/{tenant_id}/{provider}/{connector}/backfill')
def connector_backfill(
    tenant_id: str,
    provider: str,
    connector: str,
    request: Request,
    body: ConnectorPollRequest = Body(default=ConnectorPollRequest()),
    api_key: Optional[str] = Header(None, alias='x-api-key'),
) -> Dict[str, Any]:
    return connector_poll(tenant_id, provider, connector, request, body, api_key)


@router.post('/{tenant_id}/assessment/live_lane')
def build_live_lane_assessment(
    tenant_id: str,
    request: Request,
    body: LiveLaneAssessmentRequest = Body(default=LiveLaneAssessmentRequest()),
    api_key: Optional[str] = Header(None, alias='x-api-key'),
) -> Dict[str, Any]:
    if not api_key:
        raise HTTPException(status_code=401, detail='missing_api_key')
    tenant = _tenant(request, tenant_id)
    return _build_live_lane_assessment(
        request=request,
        tenant=tenant,
        providers=body.providers,
        connectors=body.connectors,
        limit_per_lane=body.limit_per_lane,
        auto_llm=body.auto_llm,
        include_email=body.include_email,
    )

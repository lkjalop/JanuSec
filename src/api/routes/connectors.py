from __future__ import annotations

from typing import Any, Dict, Iterable, Optional
import hashlib
import json
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

router = APIRouter(prefix="/api/v1/connectors", tags=["connectors-control"])


class ConnectorPollRequest(BaseModel):
    since_ts: Optional[Any] = None
    limit: int = 100
    region: Optional[str] = None
    log_group_name: Optional[str] = None
    dry_run: bool = False


class ConnectorConfigRequest(BaseModel):
    config: Dict[str, Any]


def _tenant(request: Request, tenant_id: Optional[str]) -> str:
    return resolve_tenant_id(request, tenant_id) or tenant_id or 'default'


def _enforce_scope_for_provider(provider: str) -> None:
    if not scope_allows_provider(provider):
        raise HTTPException(status_code=403, detail='provider_disabled_in_scope')


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
    elif connector_id in {'eventhub', 'entra_signin', 'entra_audit'}:
        bucket = tstate.setdefault('recent_iam_events', [])
        bucket.extend(events)
        if len(bucket) > 5000:
            del bucket[:-5000]


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
    if provider not in ('azure', 'aws'):
        return 0
    emitted = 0
    try:
        from src.api.server import _record_decision  # type: ignore
    except Exception:
        return 0
    for event in events[:200]:
        try:
            if provider == 'azure':
                decision_inputs = _azure_decision_inputs(connector, event)
            else:
                decision_inputs = _aws_decision_inputs(connector, event)
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


def _connector_config_payload(provider: str, connector: str, tenant: str) -> Dict[str, Any]:
    store = ConnectorConfigStore()
    if provider == 'azure':
        cfg = AzureConnectorConfig.from_mapping({'tenant_id': tenant, **store.load(tenant, provider, connector)})
        return cfg.redacted()
    return store.load(tenant, provider, connector)


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
    if provider == 'azure':
        cfg = AzureConnectorConfig.from_mapping({'tenant_id': tenant, **payload})
        missing = cfg.validate_for(connector)
        if missing:
            raise HTTPException(status_code=400, detail={'missing': missing})
        store.save(tenant, provider, connector, payload)
        return {'ok': True, 'tenant': tenant, 'provider': provider, 'connector': connector, 'config': cfg.redacted()}
    store.save(tenant, provider, connector, payload)
    return {'ok': True, 'tenant': tenant, 'provider': provider, 'connector': connector, 'config': payload}


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
    return {'tenant': tenant, 'provider': provider, 'connector': connector, 'status': get_connector_health(runtime, tenant, connector_id)}


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
        if provider == 'aws':
            conn, fetcher = _aws_connector(connector, body)
        elif provider == 'azure':
            conn, fetcher = _azure_connector(connector, body, tenant)
        else:
            raise HTTPException(status_code=404, detail='unknown_provider')
        if provider == 'azure':
            cfg = conn.cfg
            missing = cfg.validate_for(connector)
            if missing and not body.dry_run:
                update_connector_health(runtime, tenant, connector_id, provider=provider, status='misconfigured', ok=False, error=','.join(missing))
                persist_tenant_runtime(runtime, tenant)
                raise HTTPException(status_code=400, detail={'missing': missing})
        if body.dry_run:
            runtime_state = load_runtime_state(state_store, tenant, provider, connector)
            update_connector_health(runtime, tenant, connector_id, provider=provider, status='dry_run', ok=True, checkpoint=getattr(conn, 'ck', {}), error=runtime_state.get('last_error'))
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
        update_connector_health(runtime, tenant, connector_id, provider=provider, status='error', ok=False, error=str(exc), checkpoint=getattr(locals().get('conn', None), 'ck', {}))
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

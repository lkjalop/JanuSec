from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel

try:
    from src.security.auth import AuthContext, require_api_key
except Exception:
    try:
        from security.auth import AuthContext, require_api_key
    except Exception:
        AuthContext = None
        require_api_key = None
from src.api.runtime_state import EVENT_QUEUE, get_permission_graph, get_server_runtime_state, persist_tenant_runtime, update_connector_health
from src.domains.iam.policy_ingest import ingest_policy_to_graph

try:
    from src.collectors.iam_okta_adapter import OktaIAMCollector
except Exception:  # pragma: no cover - optional dependency
    OktaIAMCollector = None  # type: ignore

try:
    from src.collectors.iam_aad_adapter import AzureADCollector
except Exception:  # pragma: no cover - optional dependency
    AzureADCollector = None  # type: ignore

try:
    from src.domains.iam.privilege_escalation import reevaluate_on_iam_event
except Exception:  # pragma: no cover - optional dependency
    reevaluate_on_iam_event = None  # type: ignore

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/iam', tags=['iam'])


class PollRequest(BaseModel):
    since_ts: Optional[float] = None
    tenant_id: Optional[str] = None


def _is_allowed() -> bool:
    # allow when test helpers enabled or local
    return (
        os.getenv('TEST_HELPERS_ENABLED', '0').lower() in {'1', 'true', 'yes'}
        or 'PYTEST_CURRENT_TEST' in os.environ
    )


def _parse_ts(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return time.time()
        if cleaned.endswith('Z'):
            cleaned = f"{cleaned[:-1]}+00:00"
        try:
            return datetime.fromisoformat(cleaned).timestamp()
        except Exception:
            try:
                return float(cleaned)
            except Exception:
                pass
    return time.time()


def _record_connector_health(runtime, tenant: str, connector_id: Optional[str], count: int) -> None:
    if not connector_id or runtime is None:
        return
    try:
        update_connector_health(
            runtime,
            tenant,
            f'iam:{connector_id}',
            provider='iam',
            status='ok',
            ok=True,
            last_count=count,
        )
        tmap = runtime.tenants.setdefault(tenant, {})
        health = tmap.setdefault('iam_connector_health', {})
        entry = health.setdefault(connector_id, {'total_ingested': 0})
        now = time.time()
        entry['last_event_ts'] = now
        entry['last_event_count'] = count
        entry['total_ingested'] = entry.get('total_ingested', 0) + count
        # Clear any stale missing-log alert indicators so new heartbeats reset alerting state.
        entry.pop('missing_alert_event_ref', None)
        entry.pop('missing_alert_ts', None)
        entry.pop('missing_ticket_ts', None)
        entry['missing_alert_count'] = 0
        entry['missing_alert_cleared_ts'] = now
    except Exception:
        pass


def _submit_pipeline_event(evt: Dict[str, Any]) -> None:
    try:
        queue = EVENT_QUEUE
    except Exception:
        queue = None
    if not queue:
        return
    try:
        if hasattr(queue, 'enqueue'):
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(queue.enqueue(evt))
            except RuntimeError:
                asyncio.run(queue.enqueue(evt))
        elif hasattr(queue, 'enqueue_event'):
            queue.enqueue_event(evt)
        elif hasattr(queue, 'put_nowait'):
            queue.put_nowait(evt)
    except Exception:
        # best-effort; ignore enqueue failures
        pass


def _submit_pipeline_events(tenant: str, connector_id: Optional[str], canonical: List[Dict[str, Any]], raw_events: List[Dict[str, Any]]) -> None:
    for idx, event in enumerate(canonical):
        raw = raw_events[idx] if idx < len(raw_events) else {}
        payload = {
            'type': 'iam_connector_event',
            'tenant': tenant,
            'source': connector_id or event.get('provider') or 'iam',
            'domain': 'identity',
            'event': event,
            'raw': raw,
        }
        _submit_pipeline_event(payload)


def _record_and_enqueue(runtime, tenant: str, canonical: List[Dict[str, Any]], raw_events: List[Dict[str, Any]], connector_id: Optional[str]) -> None:
    if not canonical:
        return
    _record_connector_health(runtime, tenant, connector_id, len(canonical))
    _submit_pipeline_events(tenant, connector_id, canonical, raw_events)


def _extract_event_batch(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ('events', 'Records', 'records', 'entries', 'items'):
            obj = payload.get(key)
            if isinstance(obj, list):
                return [evt for evt in obj if isinstance(evt, dict)]
        return [payload]
    if isinstance(payload, list):
        return [evt for evt in payload if isinstance(evt, dict)]
    return []


def _normalize_generic_identity_event(provider: str, raw: Dict[str, Any], tenant: str) -> Dict[str, Any]:
    actor = raw.get('actor') or raw.get('user') or raw.get('principal') or raw.get('userPrincipalName')
    action = raw.get('action') or raw.get('eventType') or raw.get('operation') or raw.get('activity')
    target = raw.get('target') or raw.get('resource') or raw.get('object')
    ip = raw.get('ip') or raw.get('ipAddress') or raw.get('source_ip')
    result = raw.get('result') or raw.get('status') or raw.get('outcome')
    ts_val = raw.get('ts') or raw.get('timestamp') or raw.get('event_time') or raw.get('createdDateTime')
    return {
        'id': raw.get('id') or raw.get('uuid') or f'{provider}-{int(time.time()*1000)}',
        'tenant_id': tenant,
        'provider': provider,
        'domain': 'identity',
        'ts': _parse_ts(ts_val),
        'actor': actor,
        'action': action,
        'target': target,
        'ip': ip,
        'result': result,
        'raw': raw,
    }


def _resolve_tenant(payload: Dict[str, Any], header_value: Optional[str]) -> str:
    return header_value or payload.get('tenant_id') or payload.get('tenant') or 'default'


def _ingest_generic_connector(request: Request, payload: Dict[str, Any], connector_id: str, provider: str, tenant_header: Optional[str]) -> tuple[str, int]:
    runtime = get_server_runtime_state(request.app)
    tenant = _resolve_tenant(payload if isinstance(payload, dict) else {}, tenant_header)
    events = _extract_event_batch(payload)
    canonical = [_normalize_generic_identity_event(provider, evt, tenant) for evt in events]
    ingested = _ingest_identity_events(runtime, tenant, canonical, events, connector_id=connector_id)
    return tenant, ingested


def _normalize_okta_identity_event(raw: Dict[str, Any], tenant: str) -> Dict[str, Any]:
    actor_block = raw.get('actor') or {}
    target = (raw.get('target') or [{}])
    request_block = raw.get('request', {}) or {}
    ip_chain = request_block.get('ipChain') or []
    ip = (raw.get('client') or {}).get('ipAddress')
    if not ip and ip_chain and isinstance(ip_chain, list):
        first = ip_chain[0] if ip_chain else {}
        ip = first.get('ip')
    actor = actor_block.get('alternateId') or actor_block.get('displayName')
    if not actor and isinstance(target, list) and target:
        actor = target[0].get('alternateId') or target[0].get('displayName')
    event_type = raw.get('eventType') or raw.get('displayMessage')
    return {
        'id': raw.get('uuid') or raw.get('eventId') or raw.get('id'),
        'tenant_id': tenant,
        'provider': 'okta',
        'domain': 'identity',
        'ts': _parse_ts(raw.get('published') or raw.get('eventTime') or raw.get('timestamp')),
        'actor': actor,
        'action': event_type,
        'ip': ip,
        'result': (raw.get('outcome') or {}).get('result'),
        'target': target,
        'raw': raw,
    }


def _normalize_aad_identity_event(raw: Dict[str, Any], tenant: str) -> Dict[str, Any]:
    event = raw.get('resourceData') or raw
    initiated = (event.get('initiatedBy') or {}).get('user') or {}
    actor = initiated.get('userPrincipalName') or initiated.get('displayName') or event.get('userPrincipalName')
    ip = initiated.get('ipAddress') or event.get('ipAddress')
    status = event.get('status') or {}
    targets = event.get('targetResources')
    target = None
    if isinstance(targets, list) and targets:
        target = targets[0].get('userPrincipalName') or targets[0].get('displayName')
    return {
        'id': event.get('id'),
        'tenant_id': tenant,
        'provider': 'azure_ad',
        'domain': 'identity',
        'ts': _parse_ts(event.get('activityDateTime') or event.get('createdDateTime') or event.get('eventDateTime')),
        'actor': actor,
        'action': event.get('activityDisplayName') or event.get('operationName'),
        'ip': ip,
        'result': status.get('errorCode') or status.get('failureReason'),
        'target': target,
        'raw': event,
    }


def _record_identity_events(runtime, tenant: str, events: List[Dict[str, Any]]) -> None:
    if not events:
        return
    tmap = runtime.tenants.setdefault(tenant, {})
    ring = tmap.setdefault('recent_iam_events', [])
    ring.extend(events)
    max_len = 2000
    if len(ring) > max_len:
        del ring[:-max_len]
    try:
        persist_tenant_runtime(runtime, tenant)
    except Exception:
        pass
    for ev in events:
        try:
            runtime.sanitized_events.append({'domain': 'identity', 'tenant': tenant, 'event': ev, 'ts': ev.get('ts')})
        except Exception:
            break


def _trigger_privilege_eval(runtime, tenant: str, raw_events: List[Dict[str, Any]]) -> None:
    if not raw_events or not callable(reevaluate_on_iam_event):
        return
    for ev in raw_events:
        try:
            reevaluate_on_iam_event(ev, runtime=runtime, tenant_id=tenant)
        except Exception:
            logger.debug('iam reevaluate failed for tenant=%s', tenant, exc_info=True)


def _ingest_identity_events(runtime, tenant: str, canonical: List[Dict[str, Any]], raw_events: List[Dict[str, Any]], connector_id: Optional[str] = None) -> int:
    if not canonical:
        return 0
    _record_identity_events(runtime, tenant, canonical)
    _trigger_privilege_eval(runtime, tenant, raw_events)
    _record_and_enqueue(runtime, tenant, canonical, raw_events, connector_id)
    return len(canonical)


@router.post('/ingest_policy')
def ingest_policy(request: Request, payload: Dict[str, Any], x_tenant: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not _is_allowed():
        raise HTTPException(status_code=403, detail='forbidden')
    try:
        runtime = get_server_runtime_state(request.app)
    except Exception:
        raise HTTPException(status_code=500, detail='runtime_unavailable')
    tid = x_tenant or payload.get('tenant') or 'global'
    policy = payload.get('policy') or payload
    principal_prefix = payload.get('principal_prefix') or ''
    overrides = payload.get('weight_overrides') or {}
    # merge tenant-stored overrides (admin) with payload overrides; payload wins
    try:
        tmap = runtime.tenants.setdefault(tid, {})
        stored = tmap.get('iam_weight_overrides') or {}
        if isinstance(stored, dict):
            merged = dict(stored)
            merged.update(overrides or {})
            overrides = merged
    except Exception:
        pass

    # ensure permission graph exists
    try:
        pg = get_permission_graph(runtime, tid)
    except Exception:
        pg = None

    if pg is None:
        raise HTTPException(status_code=500, detail='permission_graph_unavailable')

    try:
        ingest_policy_to_graph(pg, policy, principal_prefix=principal_prefix, weight_overrides=overrides)
    except Exception:
        raise HTTPException(status_code=500, detail='ingest_failed')

    # persist runtime (graph stores may be persisted/map-backed elsewhere)
    try:
        persist_tenant_runtime(runtime, tid)
    except Exception:
        pass

    # optionally trigger reevaluation/correlation hooks if present on runtime
    try:
        # best-effort: call reevaluate_on_iam_event if available
        if callable(reevaluate_on_iam_event):
            reevaluate_on_iam_event({'type': 'policy_ingest', 'tenant': tid, 'ts': time.time()}, runtime=runtime, tenant_id=tid)
    except Exception:
        pass

    return {'status': 'ok', 'tenant': tid}


@router.post('/okta/webhook')
async def okta_webhook(
    request: Request,
    payload: Dict[str, Any],
    x_tenant_id: Optional[str] = Header(None, alias='x-tenant-id'),
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    challenge = request.headers.get('x-okta-verification-challenge') or payload.get('verification') or payload.get('challenge') or payload.get('verificationChallenge')
    if challenge:
        return {'verification': challenge}
    data = []
    if isinstance(payload, dict):
        if isinstance(payload.get('data'), dict):
            data = payload['data'].get('events') or []
        elif isinstance(payload.get('events'), list):
            data = payload.get('events') or []
        else:
            data = [payload]
    tenant = x_tenant_id or (payload.get('tenant') if isinstance(payload, dict) else None) or 'default'
    runtime = get_server_runtime_state(request.app)
    canonical: List[Dict[str, Any]] = []
    raw_events: List[Dict[str, Any]] = []
    for evt in data:
        if not isinstance(evt, dict):
            continue
        canonical.append(_normalize_okta_identity_event(evt, tenant))
        raw_events.append(evt)
    ingested = _ingest_identity_events(runtime, tenant, canonical, raw_events, connector_id='okta')
    return {'ok': True, 'ingested': ingested}


@router.post('/okta/poll')
def okta_poll(
    request: Request,
    body: PollRequest,
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    if OktaIAMCollector is None:
        raise HTTPException(status_code=503, detail='okta_collector_unavailable')
    tenant = body.tenant_id or 'default'
    since = body.since_ts or (time.time() - 300)
    collector = OktaIAMCollector(tenant_id=tenant)
    raw_events = collector.fetch_events(since)
    runtime = get_server_runtime_state(request.app)
    canonical = [_normalize_okta_identity_event(evt, tenant) for evt in raw_events if isinstance(evt, dict)]
    ingested = _ingest_identity_events(runtime, tenant, canonical, raw_events, connector_id='okta')
    return {'ok': True, 'ingested': ingested, 'since_ts': since}


@router.get('/azure/webhook')
async def azure_webhook_validation(validationToken: Optional[str] = Query(None, alias='validationToken')) -> Response:
    if not validationToken:
        raise HTTPException(status_code=400, detail='missing_validation_token')
    return Response(content=validationToken, media_type='text/plain')


@router.post('/azure/webhook')
async def azure_webhook(
    request: Request,
    payload: Dict[str, Any],
    x_tenant_id: Optional[str] = Header(None, alias='x-tenant-id'),
    auth: AuthContext = Depends(require_api_key),
) -> Any:
    if isinstance(payload, dict):
        tokens = payload.get('validationTokens')
        if isinstance(tokens, list) and tokens:
            return Response(content=str(tokens[0]), media_type='text/plain')
    entries = (payload.get('value') if isinstance(payload, dict) else None) or []
    tenant = x_tenant_id or (payload.get('tenant') if isinstance(payload, dict) else None) or 'default'
    runtime = get_server_runtime_state(request.app)
    canonical: List[Dict[str, Any]] = []
    raw_events: List[Dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        event = entry.get('resourceData') or entry
        if not isinstance(event, dict):
            continue
        canonical.append(_normalize_aad_identity_event(entry, tenant))
        raw_events.append(event)
    ingested = _ingest_identity_events(runtime, tenant, canonical, raw_events, connector_id='azure_ad')
    return {'ok': True, 'ingested': ingested}


@router.post('/azure/poll')
def azure_poll(
    request: Request,
    body: PollRequest,
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    if AzureADCollector is None:
        raise HTTPException(status_code=503, detail='azure_collector_unavailable')
    tenant = body.tenant_id or 'default'
    since = body.since_ts or (time.time() - 300)
    collector = AzureADCollector()
    raw_events = collector.fetch_events(since)
    runtime = get_server_runtime_state(request.app)
    canonical = [_normalize_aad_identity_event(evt, tenant) for evt in raw_events if isinstance(evt, dict)]
    ingested = _ingest_identity_events(runtime, tenant, canonical, raw_events, connector_id='azure_ad')
    return {'ok': True, 'ingested': ingested, 'since_ts': since}


@router.post('/sailpoint/webhook')
async def sailpoint_webhook(
    request: Request,
    payload: Dict[str, Any],
    x_tenant_id: Optional[str] = Header(None, alias='x-tenant-id'),
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    tenant, ingested = _ingest_generic_connector(request, payload, connector_id='sailpoint_identitynow', provider='sailpoint', tenant_header=x_tenant_id)
    return {'ok': True, 'ingested': ingested, 'tenant': tenant}


@router.post('/pingidentity/webhook')
async def pingidentity_webhook(
    request: Request,
    payload: Dict[str, Any],
    x_tenant_id: Optional[str] = Header(None, alias='x-tenant-id'),
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    tenant, ingested = _ingest_generic_connector(request, payload, connector_id='pingidentity', provider='pingidentity', tenant_header=x_tenant_id)
    return {'ok': True, 'ingested': ingested, 'tenant': tenant}


@router.post('/onelogin/webhook')
async def onelogin_webhook(
    request: Request,
    payload: Dict[str, Any],
    x_tenant_id: Optional[str] = Header(None, alias='x-tenant-id'),
    authorization: Optional[str] = Header(None, alias='Authorization'),
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    expected = os.getenv('ONELOGIN_WEBHOOK_BEARER')
    if expected and authorization:
        if authorization.strip() != f'Bearer {expected}':
            raise HTTPException(status_code=401, detail='invalid_webhook_token')
    tenant, ingested = _ingest_generic_connector(request, payload, connector_id='onelogin', provider='onelogin', tenant_header=x_tenant_id)
    return {'ok': True, 'ingested': ingested, 'tenant': tenant}


@router.post('/active_directory/import')
def active_directory_import(
    request: Request,
    payload: Dict[str, Any],
    x_tenant_id: Optional[str] = Header(None, alias='x-tenant-id'),
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    tenant, ingested = _ingest_generic_connector(request, payload, connector_id='active_directory', provider='active_directory', tenant_header=x_tenant_id)
    return {'ok': True, 'ingested': ingested, 'tenant': tenant}


@router.post('/duo/poll')
def duo_poll(
    request: Request,
    body: PollRequest,
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    # Placeholder: expect upstream collector to push via generic route
    raise HTTPException(status_code=501, detail='duo_poll_not_implemented')


@router.post('/cyberark/poll')
def cyberark_poll(
    request: Request,
    body: PollRequest,
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    raise HTTPException(status_code=501, detail='cyberark_poll_not_implemented')


@router.post('/forgerock/poll')
def forgerock_poll(
    request: Request,
    body: PollRequest,
    auth: AuthContext = Depends(require_api_key),
) -> Dict[str, Any]:
    raise HTTPException(status_code=501, detail='forgerock_poll_not_implemented')


__all__ = ['router']

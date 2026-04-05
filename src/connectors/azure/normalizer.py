from __future__ import annotations

from typing import Any, Dict

from src.connectors.correlation_keys import build_correlation_keys


def _canonical_azure_shape(
    *,
    source: str,
    tenant_id: str | None,
    event_type: Any,
    event_ts: Any,
    user: Any = None,
    ip: Any = None,
    resource: Any = None,
    action: Any = None,
    factors: list[str] | None = None,
    risk_signals: list[str] | None = None,
    raw: Dict[str, Any] | None = None,
    extra: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    base = {
        'source': source,
        'tenant_id': tenant_id,
        'event_type': event_type,
        'event_ts': event_ts,
        'user': user,
        'ip': ip,
        'resource': resource,
        'action': action,
        'factors': list(factors or []),
        'risk_signals': list(risk_signals or []),
        'raw': raw or {},
        'raw_ref': {
            'source': source,
            'event_ts': event_ts,
            'user': user,
            'resource': resource,
        },
    }
    if extra:
        base.update(extra)
    return base


def normalize_event_hub_event(event: Dict[str, Any], tenant_id: str | None = None) -> Dict[str, Any]:
    body = event.get('body') if isinstance(event.get('body'), dict) else event
    normalized = _canonical_azure_shape(
        source='azure_eventhub',
        tenant_id=tenant_id,
        event_type=body.get('eventType') or body.get('category') or body.get('operationName'),
        event_ts=body.get('time') or body.get('timestamp') or body.get('eventTime'),
        resource=body.get('resourceId'),
        action=body.get('operationName'),
        raw=body,
        extra={
            'ts': body.get('time') or body.get('timestamp') or body.get('eventTime'),
            'subscription_id': body.get('subscriptionId'),
            'resource_id': body.get('resourceId'),
        },
    )
    normalized['correlation_keys'] = build_correlation_keys(
        normalized,
        extra_values={'subscription_id': body.get('subscriptionId'), 'resource_id': body.get('resourceId')},
    )
    return normalized


def normalize_entra_signin(event: Dict[str, Any], tenant_id: str | None = None) -> Dict[str, Any]:
    actor = event.get('userPrincipalName') or ((event.get('initiatedBy') or {}).get('user') or {}).get('userPrincipalName')
    ip = event.get('ipAddress') or ((event.get('initiatedBy') or {}).get('user') or {}).get('ipAddress')
    risk_signals = []
    status = event.get('status') or {}
    status_code = status.get('errorCode') if isinstance(status, dict) else None
    risk_state = event.get('riskState') or event.get('riskLevelDuringSignIn')
    if status_code not in (None, 0, '0'):
        risk_signals.append('signin_failure')
    if risk_state:
        risk_signals.append(f"risk:{risk_state}")
    normalized = _canonical_azure_shape(
        source='azure_entra_signin',
        tenant_id=tenant_id,
        event_type='signin',
        event_ts=event.get('createdDateTime') or event.get('activityDateTime'),
        user=actor,
        ip=ip,
        resource=event.get('appDisplayName') or event.get('resourceDisplayName'),
        action=event.get('appDisplayName') or event.get('activityDisplayName') or 'signin',
        factors=['azure:signin'] + (['azure:signin_risk'] if risk_signals else []),
        risk_signals=risk_signals,
        raw=event,
        extra={
            'provider': 'azure_entra',
            'ts': event.get('createdDateTime') or event.get('activityDateTime'),
            'actor': actor,
            'status': event.get('status'),
            'operation': event.get('appDisplayName') or event.get('activityDisplayName'),
        },
    )
    normalized['correlation_keys'] = build_correlation_keys(normalized)
    return normalized


def normalize_entra_audit(event: Dict[str, Any], tenant_id: str | None = None) -> Dict[str, Any]:
    actor = ((event.get('initiatedBy') or {}).get('user') or {}).get('userPrincipalName')
    action = event.get('activityDisplayName') or event.get('category')
    target_resources = event.get('targetResources') or []
    target_names = []
    for target in target_resources:
        if isinstance(target, dict):
            name = target.get('displayName') or target.get('userPrincipalName') or target.get('id')
            if name:
                target_names.append(str(name))
    risk_signals = []
    action_text = str(action or '').lower()
    if any(tok in action_text for tok in ('role', 'privilege', 'admin', 'consent', 'credential', 'policy')):
        risk_signals.append('privilege_change')
    normalized = _canonical_azure_shape(
        source='azure_entra_audit',
        tenant_id=tenant_id,
        event_type='audit',
        event_ts=event.get('activityDateTime') or event.get('createdDateTime'),
        user=actor,
        resource=target_names[0] if target_names else None,
        action=action,
        factors=['azure:audit'] + (['azure:privilege_change'] if 'privilege_change' in risk_signals else []),
        risk_signals=risk_signals,
        raw=event,
        extra={
            'provider': 'azure_entra',
            'ts': event.get('activityDateTime') or event.get('createdDateTime'),
            'actor': actor,
            'operation': action,
            'target': target_resources,
        },
    )
    normalized['correlation_keys'] = build_correlation_keys(normalized)
    return normalized


def normalize_defender_cloud_finding(event: Dict[str, Any], tenant_id: str | None = None) -> Dict[str, Any]:
    severity = event.get('severity')
    risk_signals = [f"severity:{severity}"] if severity else []
    normalized = _canonical_azure_shape(
        source='azure_defender_cloud',
        tenant_id=tenant_id,
        event_type='defender_finding',
        event_ts=event.get('timeGenerated') or event.get('createdDateTime'),
        resource=event.get('resourceId'),
        action=event.get('title') or event.get('displayName'),
        factors=['azure:defender_cloud'],
        risk_signals=risk_signals,
        raw=event,
        extra={
            'ts': event.get('timeGenerated') or event.get('createdDateTime'),
            'severity': severity,
            'resource_id': event.get('resourceId'),
            'title': event.get('title') or event.get('displayName'),
            'category': event.get('category'),
        },
    )
    normalized['correlation_keys'] = build_correlation_keys(normalized)
    return normalized

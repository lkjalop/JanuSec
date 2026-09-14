from __future__ import annotations
import json, time
from typing import Dict, Any

def normalize_okta_event(raw: Dict[str, Any], tenant_id: str | None = None) -> Dict[str, Any]:
    # Map Okta log style to unified event
    ev: Dict[str, Any] = {
        'event_id': raw.get('id') or f"okta-{int(time.time()*1000)}",
        'tenant_id': tenant_id or raw.get('tenant') or 'default',
        'ts': time.time(),
        'ingest_source': 'okta',
        'domain': 'iam',
        'raw': raw,
        'iam': {
            'change_type': raw.get('changeType') or raw.get('eventType'),
            'roles_after': raw.get('rolesAfter'),
            'roles_before': raw.get('rolesBefore'),
            'privilege_delta_count': raw.get('privilegeDelta') or 0,
            'mfa_state_change': raw.get('mfaStateChange')
        },
        'actor': {
            'principal_id': raw.get('actor', {}).get('id') or raw.get('target', [{}])[0].get('id'),
            'principal_type': 'user'
        }
    }
    # Build initial factor hints
    ev['factors'] = []
    if ev['iam']['privilege_delta_count'] and ev['iam']['privilege_delta_count'] > 0:
        ev['factors'].append('iam:privilege_delta_observed')
    return ev


def normalize_apigw_event(raw: Dict[str, Any], tenant_id: str | None = None) -> Dict[str, Any]:
    ev: Dict[str, Any] = {
        'event_id': raw.get('id') or f"apigw-{int(time.time()*1000)}",
        'tenant_id': tenant_id or 'default',
        'ts': time.time(),
        'ingest_source': 'api_gateway',
        'domain': 'api',
        'raw': raw,
        'api': {
            'path': raw.get('path'),
            'method': raw.get('methodsSequence', [None])[-1] if raw.get('methodsSequence') else None,
            'status': raw.get('status'),
            'token_id': raw.get('tokenId') or raw.get('token_id')
        },
        'network': {
            'src_ip': raw.get('srcIp')
        }
    }
    ev['factors'] = []
    # Heuristics: many methods sequence -> add suspect factor
    seq = raw.get('methodsSequence') or []
    try:
        ev['api']['method_sequence_len'] = len(seq)
        ev['api']['method_combo_size'] = len(set(seq))
    except Exception:
        pass
    if len(set(seq)) > 3:
        ev['factors'].append('api:rare_method_combo')
    return ev


def normalize_o365_event(raw: Dict[str, Any], tenant_id: str | None = None) -> Dict[str, Any]:
    ev = {
        'event_id': raw.get('id') or f"o365-{int(time.time()*1000)}",
        'tenant_id': tenant_id or 'default',
        'ts': time.time(),
        'ingest_source': 'o365',
        'domain': 'email',
        'raw': raw,
        'email': {
            'from': raw.get('from'),
            'subject': raw.get('subject'),
            'forward_rule_added': raw.get('forwardRuleAdded', False),
            'forward_destination': raw.get('forwardDestination')
        }
    }
    ev['factors'] = []
    if ev['email']['forward_rule_added'] and ev['email']['forward_destination']:
        ev['factors'].append('email:forward_rule_new_external')
    return ev


def normalize_gmail_event(raw: Dict[str, Any], tenant_id: str | None = None) -> Dict[str, Any]:
    # Gmail API message (metadata format) normalization
    headers = {}
    try:
        for h in (raw.get('payload', {}) or {}).get('headers', []):
            name = h.get('name')
            value = h.get('value')
            if name and value:
                headers[name.lower()] = value
    except Exception:
        headers = {}
    ev = {
        'event_id': raw.get('id') or f"gmail-{int(time.time()*1000)}",
        'tenant_id': tenant_id or 'default',
        'ts': time.time(),
        'ingest_source': 'gmail',
        'domain': 'email',
        'raw': raw,
        'email': {
            'from': headers.get('from'),
            'subject': headers.get('subject'),
            'has_attachments': any(p.get('filename') for p in (raw.get('payload', {}) or {}).get('parts', []) if isinstance(p, dict)),
        },
        'headers': headers,
        'body_preview': None,
    }
    ev['factors'] = []
    return ev


def normalize_generic(raw: Dict[str, Any], tenant_id: str | None = None) -> Dict[str, Any]:
    # Best-effort passthrough mapping
    ev = {
        'event_id': raw.get('id') or raw.get('event_id') or f"evt-{int(time.time()*1000)}",
        'tenant_id': tenant_id or raw.get('tenant') or 'default',
        'ts': raw.get('ts') or time.time(),
        'ingest_source': raw.get('source') or 'generic',
        'domain': raw.get('domain') or 'endpoint',
        'raw': raw,
        'factors': raw.get('factors') or []
    }
    return ev


__all__ = [
    'normalize_okta_event', 'normalize_apigw_event', 'normalize_o365_event', 'normalize_gmail_event', 'normalize_generic'
]

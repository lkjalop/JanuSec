from __future__ import annotations

from typing import Any, Dict, List, Tuple
from datetime import datetime


# Canonical field names across domains
CANONICAL_FIELDS = {
    'email': ['message_id', 'user', 'host', 'sender', 'recipient', 'subject', 'url', 'verdict'],
    'click_event': ['message_id', 'event_id', 'user', 'url', 'verdict', 'timestamp', 'meta'],
    'identity_event': ['user', 'host', 'verdict', 'timestamp', 'meta'],
    'endpoint_event': ['host', 'process', 'file_hash', 'verdict', 'timestamp', 'meta'],
    'devops_event': ['repo', 'action', 'user', 'verdict', 'timestamp', 'meta'],
}


_CLICK_SYNONYMS = {
    'user': ['user', 'recipient', 'user_email'],
    'url': ['url', 'click_url', 'link'],
    'message_id': ['message_id', 'mid'],
    'event_id': ['event_id', 'eid'],
    'verdict': ['verdict', 'decision'],
}

_IDENTITY_SYNONYMS = {
    'user': ['user', 'principal', 'username', 'email', 'caller'],
    'host': ['host', 'computer', 'hostname', 'device', 'machine'],
    'verdict': ['verdict', 'decision', 'status'],
    'timestamp': ['timestamp', 'ts', 'eventTime', 'time'],
}

_ENDPOINT_SYNONYMS = {
    'host': ['host', 'computer', 'hostname', 'agent', 'endpoint', 'ComputerName'],
    'process': ['process', 'Image', 'exe', 'binary'],
    'file_hash': ['file_hash', 'sha256', 'hash', 'SHA256HashData'],
    'verdict': ['verdict', 'decision', 'status'],
    'timestamp': ['timestamp', 'ts', 'eventTime', 'time'],
}

_DEVOPS_SYNONYMS = {
    'repo': ['repo', 'repository', 'project'],
    'action': ['action', 'event', 'verb'],
    'user': ['user', 'actor', 'username'],
    'verdict': ['verdict', 'decision', 'status'],
    'timestamp': ['timestamp', 'ts', 'eventTime', 'time'],
}


def _first(payload: Dict[str, Any], names: List[str]) -> Any:
    for n in names:
        if n in payload and payload[n] is not None:
            return payload[n]
    return None


def normalize_click_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    norm: Dict[str, Any] = {
        'message_id': _first(payload, _CLICK_SYNONYMS['message_id']),
        'event_id': _first(payload, _CLICK_SYNONYMS['event_id']),
        'user': _first(payload, _CLICK_SYNONYMS['user']),
        'url': _first(payload, _CLICK_SYNONYMS['url']),
        'verdict': _first(payload, _CLICK_SYNONYMS['verdict']),
        'timestamp': payload.get('timestamp') or payload.get('ts') or datetime.utcnow().timestamp(),
        'meta': dict(payload.get('meta') or payload.get('raw') or {}),
    }
    # normalize common meta keys
    if 'user_agent' in payload and payload.get('user_agent'):
        norm['meta'].setdefault('ua', payload.get('user_agent'))
    if 'ip' in payload and payload.get('ip'):
        norm['meta'].setdefault('ip', payload.get('ip'))
    return norm


def validate_click_event(event: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    if not (event.get('message_id') or event.get('event_id')):
        errors.append('missing:message_id_or_event_id')
    if not event.get('user'):
        errors.append('missing:user')
    if not event.get('url'):
        errors.append('missing:url')
    try:
        ts = float(event.get('timestamp'))
        if ts <= 0:
            errors.append('invalid:timestamp')
    except Exception:
        errors.append('invalid:timestamp')
    return (len(errors) == 0, errors)


def _parse_ts(value: Any) -> float | None:
    if value is None:
        return None
    # numeric
    try:
        f = float(value)
        return f
    except Exception:
        pass
    # ISO-like strings
    if isinstance(value, str):
        try:
            v = value.rstrip('Z')
            dt = datetime.fromisoformat(v)
            return dt.timestamp()
        except Exception:
            return None
    return None


def normalize_identity_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    ts_val = _first(payload, _IDENTITY_SYNONYMS['timestamp'])
    ts = _parse_ts(ts_val) or datetime.utcnow().timestamp()
    norm: Dict[str, Any] = {
        'user': _first(payload, _IDENTITY_SYNONYMS['user']),
        'host': _first(payload, _IDENTITY_SYNONYMS['host']),
        'verdict': _first(payload, _IDENTITY_SYNONYMS['verdict']),
        'timestamp': ts,
        'meta': dict(payload.get('meta') or payload.get('raw') or {}),
    }
    # capture common context fields
    for key in ('provider', 'action', 'resource', 'role', 'roles'):
        if key in payload:
            norm['meta'].setdefault(key, payload.get(key))
    return norm


def validate_identity_event(event: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    if not (event.get('user') or event.get('host')):
        errors.append('missing:user_or_host')
    try:
        ts = float(event.get('timestamp'))
        if ts <= 0:
            errors.append('invalid:timestamp')
    except Exception:
        errors.append('invalid:timestamp')
    return (len(errors) == 0, errors)


def normalize_endpoint_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    ts_val = _first(payload, _ENDPOINT_SYNONYMS['timestamp'])
    ts = _parse_ts(ts_val) or datetime.utcnow().timestamp()
    # Process may arrive as dict or string; normalize to dict when possible
    proc = _first(payload, _ENDPOINT_SYNONYMS['process'])
    if isinstance(proc, str):
        proc = {'image': proc}
    norm: Dict[str, Any] = {
        'host': _first(payload, _ENDPOINT_SYNONYMS['host']),
        'process': proc if isinstance(proc, dict) else None,
        'file_hash': _first(payload, _ENDPOINT_SYNONYMS['file_hash']),
        'verdict': _first(payload, _ENDPOINT_SYNONYMS['verdict']),
        'timestamp': ts,
        'meta': dict(payload.get('meta') or payload.get('raw') or {}),
    }
    # common network context
    for key in ('src_ip', 'dest_ip', 'LocalIP', 'RemoteIP', 'dns_rcode'):
        if key in payload:
            norm['meta'].setdefault(key, payload.get(key))
    return norm


def validate_endpoint_event(event: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    if not (event.get('host') or event.get('process') or event.get('file_hash')):
        errors.append('missing:host_or_process_or_file_hash')
    try:
        ts = float(event.get('timestamp'))
        if ts <= 0:
            errors.append('invalid:timestamp')
    except Exception:
        errors.append('invalid:timestamp')
    return (len(errors) == 0, errors)


def normalize_devops_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    ts_val = _first(payload, _DEVOPS_SYNONYMS['timestamp'])
    ts = _parse_ts(ts_val) or datetime.utcnow().timestamp()
    norm: Dict[str, Any] = {
        'repo': _first(payload, _DEVOPS_SYNONYMS['repo']),
        'action': _first(payload, _DEVOPS_SYNONYMS['action']),
        'user': _first(payload, _DEVOPS_SYNONYMS['user']),
        'verdict': _first(payload, _DEVOPS_SYNONYMS['verdict']),
        'timestamp': ts,
        'meta': dict(payload.get('meta') or payload.get('raw') or {}),
    }
    for key in ('branch', 'commit', 'pull_request', 'pipeline_id', 'project_id'):
        if key in payload:
            norm['meta'].setdefault(key, payload.get(key))
    return norm


def validate_devops_event(event: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    if not (event.get('repo') or event.get('action') or event.get('user')):
        errors.append('missing:repo_or_action_or_user')
    try:
        ts = float(event.get('timestamp'))
        if ts <= 0:
            errors.append('invalid:timestamp')
    except Exception:
        errors.append('invalid:timestamp')
    return (len(errors) == 0, errors)


def normalize_and_validate(domain: str, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], bool, List[str]]:
    """Return (normalized, is_valid, errors) for supported domains."""
    if domain == 'click_event':
        norm = normalize_click_event(payload)
        ok, errs = validate_click_event(norm)
        return norm, ok, errs
    if domain == 'identity_event':
        norm = normalize_identity_event(payload)
        ok, errs = validate_identity_event(norm)
        return norm, ok, errs
    if domain == 'endpoint_event':
        norm = normalize_endpoint_event(payload)
        ok, errs = validate_endpoint_event(norm)
        return norm, ok, errs
    if domain == 'devops_event':
        norm = normalize_devops_event(payload)
        ok, errs = validate_devops_event(norm)
        return norm, ok, errs
    # passthrough for other domains until implemented
    return dict(payload), True, []


__all__ = ['CANONICAL_FIELDS', 'normalize_and_validate']

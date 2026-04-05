from __future__ import annotations
from typing import Any, Dict, List

# Minimal normalization of Azure Defender/Policy events to platform posture findings
# Expected platform shape per finding: { id, type, resource, severity, source_ts(optional) }

_SEVERITY_MAP = {
    'High': 'high',
    'Medium': 'medium',
    'Low': 'low',
    'Critical': 'critical',
}

_TYPE_MAP_HINTS = {
    'SecurityGroupOpen': 'cloud:sg_open_0_0_0_0',
    'PublicBucket': 'cloud:public_bucket',
    'IAMWildcard': 'iam:overpriv_wildcard',
    'IAMKeyNoMFA': 'iam:key_no_mfa',
}


def normalize_defender_event(evt: Dict[str, Any]) -> Dict[str, Any]:
    fid = evt.get('id') or evt.get('findingId') or evt.get('name') or evt.get('policyDefinitionId')
    category = evt.get('category') or evt.get('type') or evt.get('recommendationType')
    resource = (
        evt.get('resourceId')
        or (evt.get('resource') or {}).get('id')
        or evt.get('properties', {}).get('resourceId')
    )
    sev_raw = evt.get('severity') or evt.get('properties', {}).get('severity')
    severity = _SEVERITY_MAP.get(str(sev_raw), str(sev_raw or '').lower())
    t_hint = _TYPE_MAP_HINTS.get(str(category)) if category else None
    ftype = t_hint or ('cloud:' + str(category).lower() if category else 'cloud:unknown')
    source_ts = evt.get('eventTime') or evt.get('timeGenerated') or evt.get('properties', {}).get('timeGenerated')
    try:
        if isinstance(source_ts, str) and source_ts:
            import datetime
            from datetime import timezone
            dt = datetime.datetime.fromisoformat(source_ts.replace('Z', '+00:00'))
            source_ts = dt.replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        pass
    return {
        'id': fid or 'unknown',
        'type': ftype,
        'resource': resource or 'unknown',
        'severity': severity or 'low',
        'source_ts': source_ts,
    }


def build_posture_payload(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings = [normalize_defender_event(e) for e in events if isinstance(e, dict)]
    return {'findings': findings}

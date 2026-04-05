from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List


def _parse_ts(val: str | None) -> float | None:
    if not val:
        return None
    try:
        # accept ISO8601
        return float(datetime.fromisoformat(val.replace('Z', '+00:00')).timestamp())
    except Exception:
        return None


def normalize_defender_event(evt: Dict[str, Any]) -> Dict[str, Any]:
    # Attempt to normalize multiple known shapes from sample fixtures
    out: Dict[str, Any] = {}
    # ID
    out['id'] = evt.get('id') or evt.get('findingId') or evt.get('name') or 'unknown'
    # Type mapping
    typ = evt.get('type') or evt.get('category') or evt.get('recommendationType')
    if typ:
        typ = str(typ)
        # simple mapping hints
        if 'PublicBucket' in typ or 'Storage' in (evt.get('resourceId') or ''):
            out['type'] = 'cloud:public_bucket'
        elif 'SecurityGroup' in typ or 'SecurityGroupOpen' in typ:
            out['type'] = 'cloud:sg_open_0_0_0_0'
        elif 'IAM' in typ or 'KeyNoMFA' in typ or 'IAMKeyNoMFA' in typ:
            out['type'] = 'iam:key_no_mfa'
        else:
            out['type'] = f'cloud:{typ.lower()}'
    else:
        out['type'] = 'cloud:unknown'
    # Resource
    res = evt.get('resource') or {}
    res_id = evt.get('resourceId') or (res.get('id') if isinstance(res, dict) else None)
    out['resource'] = res_id or 'unknown'
    # Severity mapping
    sev = evt.get('severity') or (evt.get('properties') or {}).get('severity')
    if isinstance(sev, str):
        s = sev.lower()
        if s.startswith('h'):
            out['severity'] = 'high'
        elif s.startswith('m'):
            out['severity'] = 'medium'
        elif s.startswith('c'):
            out['severity'] = 'critical'
        else:
            out['severity'] = 'low'
    else:
        out['severity'] = 'low'
    # Timestamp
    ts = evt.get('eventTime') or (evt.get('properties') or {}).get('timeGenerated') or evt.get('timeGenerated')
    out_ts = _parse_ts(ts)
    if out_ts is not None:
        out['source_ts'] = out_ts
    return out


def build_posture_payload(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    for e in events:
        n = normalize_defender_event(e)
        findings.append({
            'id': n.get('id'),
            'type': n.get('type'),
            'resource': n.get('resource'),
            'severity': n.get('severity'),
            'source_ts': n.get('source_ts')
        })
    return {'findings': findings}
from datetime import datetime
from typing import List, Dict


def normalize_defender_event(evt: Dict) -> Dict:
    # simple normalization matching test expectations
    category_map = {
        'IAMKeyNoMFA': 'iam:key_no_mfa',
        'SecurityGroupOpen': 'cloud:sg_open_0_0_0_0',
        'PublicBucket': 'cloud:public_bucket',
    }
    out = {}
    out['id'] = evt.get('id')
    out['type'] = category_map.get(evt.get('category'), evt.get('category').lower() if evt.get('category') else None)
    out['resource'] = evt.get('resourceId')
    out['severity'] = (evt.get('severity') or '').lower()
    ts = evt.get('eventTime')
    if ts:
        try:
            out['source_ts'] = datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp()
        except Exception:
            out['source_ts'] = None
    return out


def build_posture_payload(events: List[Dict]) -> Dict:
    findings = [normalize_defender_event(e) for e in events]
    return {'findings': findings}

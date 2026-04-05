from typing import Dict, Any
from ..canonical_event import CanonicalEvent

def parse_iam_record(rec: Dict[str, Any]) -> CanonicalEvent:
    mapped = {
        'timestamp': rec.get('timestamp'),
        'tenant': rec.get('tenant'),
        'source_type': 'iam',
        'user': rec.get('actor') or rec.get('user'),
        'action': rec.get('action'),
        'policy_id': rec.get('policy'),
        'privilege_level_before': rec.get('prev_role') or rec.get('privilege_level_before'),
        'privilege_level_after': rec.get('new_role') or rec.get('privilege_level_after'),
    }
    raw_sub = rec.get('raw')
    if isinstance(raw_sub, dict):
        for k, v in raw_sub.items():
            mapped.setdefault(k, v)
    return CanonicalEvent.from_dict(mapped)

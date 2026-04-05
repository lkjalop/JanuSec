from typing import Dict, Any
from ..canonical_event import CanonicalEvent

def parse_api_record(rec: Dict[str, Any]) -> CanonicalEvent:
    mapped = {
        'timestamp': rec.get('timestamp'),
        'tenant': rec.get('tenant'),
        'source_type': 'api',
        'user': rec.get('user'),
        'api_endpoint': rec.get('endpoint') or rec.get('api_endpoint'),
        'method': rec.get('method'),
        'status': rec.get('status'),
        'src_ip': rec.get('src_ip'),
    }
    raw_sub = rec.get('raw')
    if isinstance(raw_sub, dict):
        for k, v in raw_sub.items():
            mapped.setdefault(k, v)
    for k in ['auth_token']:
        if k in rec and k not in mapped:
            mapped[k] = rec[k]
    return CanonicalEvent.from_dict(mapped)

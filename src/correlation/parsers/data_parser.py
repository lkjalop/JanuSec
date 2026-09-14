from typing import Dict, Any
from ..canonical_event import CanonicalEvent

def parse_data_record(rec: Dict[str, Any]) -> CanonicalEvent:
    mapped = {
        'timestamp': rec.get('timestamp'),
        'tenant': rec.get('tenant'),
        'source_type': 'data',
        'user': rec.get('user'),
        'data_volume_bytes': rec.get('data_volume_bytes') if rec.get('data_volume_bytes') is not None else rec.get('volume'),
        'direction': rec.get('direction'),
        'repository': rec.get('repository'),
    }
    raw_sub = rec.get('raw')
    if isinstance(raw_sub, dict):
        for k, v in raw_sub.items():
            mapped.setdefault(k, v)
    return CanonicalEvent.from_dict(mapped)

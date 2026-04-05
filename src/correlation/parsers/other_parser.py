from typing import Dict, Any
from ..canonical_event import CanonicalEvent

def parse_other_record(rec: Dict[str, Any]) -> CanonicalEvent:
    mapped = {
        'timestamp': rec.get('timestamp'),
        'tenant': rec.get('tenant'),
        'source_type': 'other',
        'user': rec.get('actor') or rec.get('user'),
        'config_change_type': rec.get('change_type'),
    }
    return CanonicalEvent.from_dict(mapped)

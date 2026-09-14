from typing import Dict, Any
from ..canonical_event import CanonicalEvent

def parse_endpoint_record(rec: Dict[str, Any]) -> CanonicalEvent:
    mapped = {
        'timestamp': rec.get('timestamp'),
        'tenant': rec.get('tenant'),
        'source_type': 'endpoint',
        'host': rec.get('host'),
        'process': rec.get('process'),
        'pid': rec.get('pid'),
        'file_hash': rec.get('hash'),
        'user': rec.get('user'),
    }
    # merge raw sub-dict to allow factor heuristics to inspect registry_change / autorun markers
    raw_sub = rec.get('raw')
    if isinstance(raw_sub, dict):
        for k, v in raw_sub.items():
            mapped.setdefault(k, v)
    # pass through top-level keys that may be used by heuristics if present
    for k in ['registry_change', 'autorun_entry', 'parent_process']:
        if k in rec and k not in mapped:
            mapped[k] = rec[k]
    return CanonicalEvent.from_dict(mapped)

from typing import Dict, Any
from ..canonical_event import CanonicalEvent

def parse_network_record(rec: Dict[str, Any]) -> CanonicalEvent:
    mapped = {
        'timestamp': rec.get('timestamp'),
        'tenant': rec.get('tenant'),
        'source_type': 'network',
        'src_ip': rec.get('src_ip'),
        'dst_ip': rec.get('dst_ip'),
        'src_port': rec.get('src_port'),
        'dst_port': rec.get('dst_port'),
        'protocol': rec.get('proto'),
        'domain': rec.get('domain'),
    }
    return CanonicalEvent.from_dict(mapped)

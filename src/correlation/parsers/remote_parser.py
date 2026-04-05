from typing import Dict, Any
from ..canonical_event import CanonicalEvent

def parse_remote_record(rec: Dict[str, Any]) -> CanonicalEvent:
    mapped = {
        'timestamp': rec.get('timestamp'),
        'tenant': rec.get('tenant'),
        'source_type': 'remote',
        'user': rec.get('vpn_user') or rec.get('user'),
        'src_ip': rec.get('src_ip'),
        'dst_ip': rec.get('dst_ip'),
        'auth_method': rec.get('auth_method'),
        'mfa_result': rec.get('mfa'),
        'status': rec.get('status'),
        'outcome': rec.get('outcome'),
        'geo_src': rec.get('geo_src'),
    }
    return CanonicalEvent.from_dict(mapped)

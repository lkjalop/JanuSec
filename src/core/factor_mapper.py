from __future__ import annotations

from typing import Dict, List, Tuple
from src.core.threat_modeling.factor_taxonomy import _FACTOR_MAP

# Simple canonical field -> factor hints. Can be expanded.
_FIELD_TO_FACTORS = {
    'sha256': ['endpoint:unsigned_driver_install_flow', 'endpoint:unsigned_exec'],
    'file_hash': ['endpoint:unsigned_driver_install_flow', 'endpoint:unsigned_exec'],
    'ip': ['net:tor_outbound_contact', 'net:doh_tunnel_candidate', 'net:ja3_ja4_novel_pair'],
    'domain': ['dns:tunnel_suspected', 'net:sni_dns_nx_spike'],
    'user': ['identity:pass_the_cookie_reuse', 'identity:session_stitching_anomaly'],
    'mailbox': ['email:mailbox_rule_burst', 'email:display_name_impersonation'],
}


def score_candidates_from_event(event: Dict[str, any]) -> List[Tuple[str, int]]:
    """Return ranked (factor, score) candidates based on canonical fields and taxonomy matches."""
    scores: Dict[str, int] = {}
    # Check canonical fields first
    for field, factors in _FIELD_TO_FACTORS.items():
        if field in event and event.get(field):
            for f in factors:
                scores[f] = scores.get(f, 0) + 5
    # Look for keys that match domain tokens in taxonomy
    vals = ' '.join(str(v).lower() for v in event.values() if v)
    for f in _FACTOR_MAP.keys():
        token = f.split(':', 1)[-1]
        if token and token.replace('_', ' ') in vals:
            scores[f] = scores.get(f, 0) + 3
    # Return sorted list
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return ranked

"""MITRE ATT&CK + STRIDE mapping helpers.

Lightweight static mapping. In production these could be versioned or loaded
from a managed file. Keep minimal to avoid bloat.
"""
from __future__ import annotations
from typing import List, Dict, Set

# Simplified demonstration mapping factor -> ATT&CK tactics
MITRE_MAP: Dict[str, List[str]] = {
    'lateral_movement_candidate': ['TA0008'],
    'privilege_escalation_attempt': ['TA0004'],
    'persistence_pattern': ['TA0003'],
    'credential_access_pattern': ['TA0006'],
    'exfil_suspect': ['TA0010'],
    'dns_tunnel_pattern': ['TA0011'],
    'beacon_like_30s': ['TA0011'],
    # Newly added (monitor cardinality):
    'graph_host_multiuser_hotspot': ['TA0008'],
    'graph_user_proc_burst': ['TA0002'],  # Execution spike
    'auth_fail_burst_5m': ['TA0006'],
}

# STRIDE classification examples
STRIDE_MAP: Dict[str, List[str]] = {
    'lateral_movement_candidate': ['Elevation of Privilege'],
    'privilege_escalation_attempt': ['Elevation of Privilege'],
    'credential_access_pattern': ['Information Disclosure'],
    'dns_tunnel_pattern': ['Information Disclosure'],
    'persistence_pattern': ['Tampering'],
}

PREFIX_MITRE = 'mitre_'
PREFIX_STRIDE = 'stride_'

def map_factors(factors: List[str]) -> List[str]:
    out: Set[str] = set()
    for f in factors:
        base = f.split(':',1)[0]
        if base in MITRE_MAP:
            for t in MITRE_MAP[base]:
                out.add(f'{PREFIX_MITRE}{t}')
        if base in STRIDE_MAP:
            for s in STRIDE_MAP[base]:
                out.add(f'{PREFIX_STRIDE}{s.lower().replace(" ", "_")}')
    return sorted(out)

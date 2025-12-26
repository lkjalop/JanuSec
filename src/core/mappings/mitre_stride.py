"""(Deprecated) MITRE ATT&CK + STRIDE mapping helpers.

DEPRECATION: This module is retained for backward compatibility. New code
should use `core.threat_modeling.factor_taxonomy.aggregate_threat_model` which
provides unified STRIDE / DREAD / MAESTRO outputs. This module now delegates
STRIDE category derivation to the unified taxonomy where possible and only
falls back to the legacy static maps if needed.
"""
from __future__ import annotations

from typing import Dict, List, Set
import re

from core.threat_modeling.factor_taxonomy import aggregate_threat_model  # type: ignore

# Simplified demonstration mapping factor -> ATT&CK tactics
MITRE_MAP: dict[str, list[str]] = {
    'lateral_movement_candidate': ['TA0008'],
    'lateral_movement_composite': ['TA0008'],
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
    # Hunt lanes (new)
    'lane_host_pivot': ['TA0008'],
    'lane_privilege_misuse': ['TA0004'],
    'graph_motif_user_proc_auth': ['TA0004','TA0008'],
    'graph_motif_auth_burst_remote_tool_dc': ['TA0008'],
}

# Email domain Phase 1 factor mappings (BEC/Phishing)
MITRE_MAP.update({
    'email:display_name_spoof': ['TA0003'],
    'email:financial_keywords': ['TA0040'],
    'email:urgency_keywords': ['TA0040'],
    'email:reply_to_mismatch': ['TA0001'],
    'email:sender_spoofed_thread': ['TA0003'],
})

# STRIDE classification examples
STRIDE_MAP: dict[str, list[str]] = {
    'lateral_movement_candidate': ['Elevation of Privilege'],
    'lateral_movement_composite': ['Elevation of Privilege'],
    'privilege_escalation_attempt': ['Elevation of Privilege'],
    'credential_access_pattern': ['Information Disclosure'],
    'dns_tunnel_pattern': ['Information Disclosure'],
    'persistence_pattern': ['Tampering'],
    # Hunt lanes (new)
    'lane_host_pivot': ['Elevation of Privilege'],
    'lane_privilege_misuse': ['Elevation of Privilege'],
}

# STRIDE entries for email Phase 1
STRIDE_MAP.update({
    'email:display_name_spoof': ['Spoofing'],
    'email:financial_keywords': ['Repudiation'],
    'email:urgency_keywords': ['Repudiation'],
    'email:reply_to_mismatch': ['Spoofing'],
    'email:sender_spoofed_thread': ['Spoofing'],
})

PREFIX_MITRE = 'mitre_'
PREFIX_STRIDE = 'stride_'

# Canonical STRIDE names we want to emit
_CANONICAL_STRIDE = {
    'spoofing': 'spoofing',
    'tampering': 'tampering',
    'repudiation': 'repudiation',
    'information_disclosure': 'information_disclosure',
    'info_leak': 'information_disclosure',
    'information': 'information_disclosure',
    'denial_of_service': 'denial_of_service',
    'dos': 'denial_of_service',
    'denial': 'denial_of_service',
    'availability': 'denial_of_service',
    'elevation_of_privilege': 'elevation_of_privilege',
    'elevation': 'elevation_of_privilege',
    'privilege_elevation': 'elevation_of_privilege',
    'impact': 'impact',
}

def _normalize_stride_name(name: str) -> str:
    """Normalize various STRIDE category tokens into canonical, lowercased underscore form.

    Examples:
      'Elevation of Privilege' -> 'elevation_of_privilege'
      'elevation' -> 'elevation_of_privilege'
      'information_disclosure' -> 'information_disclosure'
    """
    if not name:
        return name
    n = name.lower().replace(' ', '_')
    # map short forms to canonical
    return _CANONICAL_STRIDE.get(n, n)


def map_factors(factors: list[str]) -> list[str]:  # pragma: no cover - thin wrapper
    out: set[str] = set()
    # Attempt unified model first for STRIDE categories
    try:
        model = aggregate_threat_model(factors)
        stride = (model.get('stride') or {}).get('categories', [])
        for s in stride:
            norm = _normalize_stride_name(s)
            out.add(f'{PREFIX_STRIDE}{norm}')
    except Exception:
        pass
    # Fallback: if any factor embeds explicit MITRE tokens (T#### or TA####), expose them
    try:
        for f in factors:
            if not isinstance(f, str):
                continue
            # find technique tokens
            for m in re.findall(r'T\d{4}(?:\.\d{3})?', f, flags=re.IGNORECASE):
                out.add(f'{PREFIX_MITRE}{m.upper()}')
            for m in re.findall(r'TA\d{4}', f, flags=re.IGNORECASE):
                out.add(f'{PREFIX_MITRE}{m.upper()}')
    except Exception:
        pass
    # Legacy MITRE & STRIDE fallback
    for f in factors:
        base = f.split(':', 1)[0]
        if base in MITRE_MAP:
            for t in MITRE_MAP[base]:
                out.add(f'{PREFIX_MITRE}{t}')
        if base in STRIDE_MAP:  # only add if not already present
            for s in STRIDE_MAP[base]:
                tag = f'{PREFIX_STRIDE}{_normalize_stride_name(s)}'
                out.add(tag)
    # Normalize output ordering
    return sorted(out)

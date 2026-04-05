"""Mapping of observed enrichments/actions to explainable frameworks (MITRE/STRIDE/DREAD).

This module contains simple rule tables and lookup helpers. It's intentionally
small and deterministic to aid explainability and unit testing.

The public function `map_enrichments` accepts either:
 - a list of enrichment key strings (legacy), or
 - a dict mapping enrichment key -> observed value/context

The return shape is a dict with `mitre`, `stride`, `dread` (components), and `details`.
"""
from __future__ import annotations

from typing import Dict, List, Any, Union

# Expanded MITRE/STRIDE lookup tables (compact subset)
MITRE_TABLE = {
    'ebpf:container_escape': ['T1610'],
    'ebpf:priv_escalation': ['T1548'],
    'falco_rule:shell_spawn': ['T1059.001'],
    'network:port_scan': ['T1595'],
    'lateral:ssh': ['T1021.004'],
    'lateral:smb': ['T1021.002'],
    'supply_chain:download_component': ['T1195'],
}

STRIDE_TABLE = {
    'ebpf:container_escape': ['Tampering'],
    'ebpf:priv_escalation': ['Elevation of Privilege'],
    'falco_rule:shell_spawn': ['Tampering'],
    'network:port_scan': ['Information Disclosure'],
}

# RULES map enrichment key -> mapping metadata used by explainers
RULES: Dict[str, Dict[str, Any]] = {
    'ebpf:container_escape': {
        'mitre': MITRE_TABLE['ebpf:container_escape'],
        'stride': STRIDE_TABLE.get('ebpf:container_escape', []),
        'dread': {'damage': 0.9, 'exploit': 0.8}
    },
    'ebpf:priv_escalation': {
        'mitre': MITRE_TABLE['ebpf:priv_escalation'],
        'stride': STRIDE_TABLE.get('ebpf:priv_escalation', []),
        'dread': {'damage': 0.8, 'exploit': 0.7}
    },
    'falco_rule:shell_spawn': {
        # include parent technique T1059 in addition to sub-technique T1059.001
        'mitre': ['T1059'] + MITRE_TABLE['falco_rule:shell_spawn'],
        'stride': STRIDE_TABLE.get('falco_rule:shell_spawn', []),
        'dread': {'discover': 0.6}
    },
    'network:port_scan': {
        'mitre': MITRE_TABLE['network:port_scan'],
        'stride': STRIDE_TABLE.get('network:port_scan', []),
        'dread': {'discover': 0.5}
    },
    'lateral:ssh': {
        'mitre': MITRE_TABLE['lateral:ssh'],
        'stride': STRIDE_TABLE.get('lateral:ssh', []),
        'dread': {'damage': 0.6}
    }
}


def map_enrichments(enrichments: Union[List[str], Dict[str, Any]]) -> Dict[str, Any]:
    mitre: List[str] = []
    stride: List[str] = []
    dread = {'damage': 0.0, 'repro': 0.5, 'exploit': 0.5, 'affected': 0.5, 'discover': 0.5}
    details: List[Dict[str, Any]] = []

    # normalize input to dict: key -> observed_value
    items: Dict[str, Any]
    if isinstance(enrichments, list):
        items = {k: True for k in enrichments}
    else:
        items = enrichments or {}

    for k, observed in items.items():
        rule = RULES.get(k)
        if rule:
            mitre += rule.get('mitre', [])
            stride += rule.get('stride', [])
            for dk, dv in rule.get('dread', {}).items():
                dread[dk] = max(dread.get(dk, 0.0), float(dv))
            details.append({'enrichment': k, 'mapped': rule, 'observed': observed})

    return {'mitre': sorted(set(mitre)), 'stride': sorted(set(stride)), 'dread': dread, 'details': details}


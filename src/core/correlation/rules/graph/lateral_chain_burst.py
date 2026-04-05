"""Placeholder rule: lateral_chain_burst
"""
from __future__ import annotations
from typing import Dict, Any, List
from ..registry import register_rule

# Prototype uses a HopGraph join helper to look for multiple host-to-host execs
from src.core.correlation.hop_helpers import hopgraph_neighbors

@register_rule(name='corr_lateral_chain_burst', mitre=['T1021','T1071'], factors_required=['host','process','neighbor_hosts'], window_seconds=900, severity='high', confidence_boost=0.5)
def lateral_chain_burst(event: Dict[str, Any]) -> bool:
    try:
        host = event.get('host')
        proc = str(event.get('process') or '')
        # Use hopgraph helper to find adjacent hosts with suspicious process
        neighbors: List[Dict[str,Any]] = hopgraph_neighbors(host, process_contains='psexec|wmiexec|winrm|ssh')
        if neighbors and len(neighbors) >= 2:
            return True
    except Exception:
        return False
    return False

# DUPLICATE_DISABLED decorator for rule graph_lateral_chain_burst in src\core\correlation\rules\graph\lateral_chain_burst.py
@register_rule(name='graph_lateral_chain_burst', mitre=['T1021'], factors_required=['graph_lateral_chain_len'], window_seconds=3600, severity='high', confidence_boost=0.5)
def graph_lateral_chain_burst(event: Dict[str, Any]) -> bool:
    try:
        # Expect injected by hopgraph integration layer
        chain_len = int(event.get('graph_lateral_chain_len') or 0)
        rapid = bool(event.get('graph_lateral_rapid'))
        if chain_len >= 3 and rapid:
            return True
    except Exception:
        pass
    return False

__all__ = ["graph_lateral_chain_burst"]
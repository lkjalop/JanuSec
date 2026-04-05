from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule
from src.core.correlation.hop_helpers import hopgraph_neighbors


@register_rule(name='corr_graph_week1_summary', mitre=['T1086'], factors_required=['host','process'], window_seconds=1200, severity='medium', confidence_boost=0.3)
def graph_week1_summary(event: Dict[str, Any]) -> bool:
    host = event.get('host')
    if not host:
        return False
    neigh = hopgraph_neighbors(host)
    return bool(neigh)


@register_rule(name='lm_graph_chain_len3', mitre=['T1021'], factors_required=['graph_lateral_chain_len'], window_seconds=3600, severity='high', confidence_boost=0.35)
def lm_graph_chain_len3(e: Dict[str,Any]) -> bool:
    try:
        return int(e.get('graph_lateral_chain_len') or 0) >= 3
    except Exception:
        return False

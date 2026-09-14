"""Detect remote jump host chains and emit 'remote:jump_host_chain' factor.

Robust across hopgraph shapes: supports adjacency list of tuples
or hopgraph.get_outbound_edges(user_node) which may return dict-like edges.
"""
from __future__ import annotations
import time
from typing import Optional
from src.core.factors.emission_tracker import record_emission

# Config
WINDOW_SECONDS = int(__import__('os').environ.get('REMOTE_JUMP_WINDOW_SECONDS','900') or 900)
MIN_HOPS = int(__import__('os').environ.get('REMOTE_JUMP_MIN_HOPS','2') or 2)


def detect_and_emit(hopgraph, user: str, now: float | None = None) -> bool:
    """Scan recent remote_access edges for user and if chain of distinct hosts >= MIN_HOPS, emit factor on user node.

    Returns True if factor emitted.
    """
    if hopgraph is None or not user:
        return False
    now = now or time.time()
    cutoff = now - WINDOW_SECONDS
    user_node = f'user:{user}'
    emitted = False
    try:
        edges = []
        if hasattr(hopgraph, 'get_outbound_edges'):
            edges = hopgraph.get_outbound_edges(user_node) or []
        else:
            adj = getattr(hopgraph, 'adj', {})
            edges = adj.get(user_node, []) if isinstance(adj, dict) else []

        hosts = []
        for e in edges:
            # Support both tuple entries and dict-like edges
            try:
                if isinstance(e, (list, tuple)) and len(e) >= 3:
                    dst, et, ts = e[0], e[1], e[2]
                else:
                    dst = e.get('to') or e.get('dst') or e.get('host')
                    et = e.get('type') or e.get('edge')
                    ts = e.get('ts', now)
                if et != 'remote_access':
                    continue
                if ts < cutoff:
                    continue
                if dst and str(dst).startswith('host:'):
                    hosts.append(dst)
            except Exception:
                continue

        # Distinct hosts in order seen
        distinct = []
        for h in hosts:
            if h not in distinct:
                distinct.append(h)
        if len(distinct) >= (MIN_HOPS + 1):
            hopgraph.add_node_factor(user_node, 'remote:jump_host_chain')
            try:
                record_emission('remote:jump_host_chain', decision_id=None, node_ids=[user_node])
            except Exception:
                pass
            emitted = True
    except Exception:
        emitted = False
    return emitted

__all__ = ['detect_and_emit']

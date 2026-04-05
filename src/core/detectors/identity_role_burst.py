"""Detect bursts of role changes for an identity and emit a factor.

Emits 'identity:role_mutation_burst' when a principal has >= MIN_CHANGES within WINDOW_SECONDS.
Debounces emissions per principal for DEBOUNCE_SECONDS.
"""
from __future__ import annotations
import time
from typing import Optional
from src.core.factors.emission_tracker import record_emission

_HISTORY: dict[str, list[float]] = {}
_LAST_EMIT: dict[str, float] = {}
WINDOW_SECONDS = int(__import__('os').environ.get('IDENTITY_ROLE_BURST_WINDOW', '300') or 300)
MIN_CHANGES = int(__import__('os').environ.get('IDENTITY_ROLE_BURST_MIN', '3') or 3)
DEBOUNCE_SECONDS = int(__import__('os').environ.get('IDENTITY_ROLE_BURST_DEBOUNCE', '3600') or 3600)


def check_and_emit(hopgraph, principal: str, now: Optional[float] = None) -> bool:
    """Record a role change for principal and emit factor if burst detected."""
    if not principal:
        return False
    now = now or time.time()
    hist = _HISTORY.setdefault(principal, [])
    hist.append(now)
    # prune old
    cutoff = now - WINDOW_SECONDS
    while hist and hist[0] < cutoff:
        hist.pop(0)
    if len(hist) >= MIN_CHANGES:
        last = _LAST_EMIT.get(principal, 0)
        if (now - last) < DEBOUNCE_SECONDS:
            return False
        node = f'identity:{principal}'
        try:
            hopgraph.add_node_factor(node, 'identity:role_mutation_burst')
        except Exception:
            pass
        try:
            record_emission('identity:role_mutation_burst', decision_id=None, node_ids=[node])
        except Exception:
            pass
        _LAST_EMIT[principal] = now
        return True
    return False


__all__ = ['check_and_emit']

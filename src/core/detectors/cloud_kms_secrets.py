"""Detect spikes in KMS/secrets access for a principal and emit anomaly factor."""
from __future__ import annotations
import time
from typing import Optional
from collections import deque
from src.core.factors.emission_tracker import record_emission

_COUNTS: dict[str, deque[float]] = {}
WINDOW = int(__import__('os').environ.get('CLOUD_KMS_WINDOW', '300') or 300)
SPIKE_MULT = float(__import__('os').environ.get('CLOUD_KMS_SPIKE_MULT', '3.0') or 3.0)
BASELINE_MIN = int(__import__('os').environ.get('CLOUD_KMS_BASELINE_MIN', '3') or 3)


def record_access(hopgraph, principal: str, now: Optional[float] = None) -> bool:
    if not principal:
        return False
    now = now or time.time()
    dq = _COUNTS.setdefault(principal, deque())
    dq.append(now)
    cutoff = now - WINDOW
    while dq and dq[0] < cutoff:
        dq.popleft()
    # baseline estimation: average per window over previous history length-1
    count = len(dq)
    if count < BASELINE_MIN:
        return False
    # simple baseline: historical mean = previous_count (exclude latest)
    # for demo purposes estimate baseline as BASELINE_MIN
    baseline = BASELINE_MIN
    if count > SPIKE_MULT * baseline:
        node = f'identity:{principal}'
        try:
            hopgraph.add_node_factor(node, 'cloud:kms_secrets_access_anomaly')
        except Exception:
            pass
        try:
            record_emission('cloud:kms_secrets_access_anomaly', decision_id=None, node_ids=[node])
        except Exception:
            pass
        return True
    return False


__all__ = ['record_access']

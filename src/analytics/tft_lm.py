from __future__ import annotations

"""TFT-lite scaffold: offline predictive LM risk (cheap placeholder).

This is a CPU-friendly stand-in for a small temporal fusion transformer.
It computes a rolling EWMA per entity (user/host) from recent LM signals
and outputs a normalized 0..1 risk. Swap the core scorer with a true TFT
when infra is available.
"""

import json
import math
import os
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, Tuple


def _ewma(prev: float, x: float, alpha: float = 0.2) -> float:
    return alpha * x + (1 - alpha) * prev


def compute_predictive_risk(events: Iterable[dict]) -> Dict[Tuple[str, str], float]:
    """Return {(tenant, entity): risk} using a few LM-centric signals as proxy.

    Signals considered: host_pivot factors, privilege_misuse factors, graph motifs.
    """
    risk: Dict[Tuple[str,str], float] = defaultdict(float)
    last: Dict[Tuple[str,str], float] = {}
    counts: Dict[Tuple[str,str], int] = defaultdict(int)
    for ev in events:
        tenant = ev.get('tenant_id') or 'public'
        user = (ev.get('user') or '').lower()
        host = (ev.get('host') or '').lower()
        entity = user or host or 'unknown'
        key = (tenant, entity)
        facs = set(ev.get('factors') or [])
        # score per event 0..1 from presence of signals
        s = 0.0
        if any(str(f).startswith(('lane_host_pivot:', 'lane_privilege_misuse:')) for f in facs):
            s += 0.5
        if 'lateral_movement_composite' in facs:
            s += 0.4
        if any(f in facs for f in ('graph_motif_user_proc_auth','graph_motif_auth_burst_remote_tool_dc','graph_motif_auth_burst_remote_tool_same_subnet')):
            s += 0.3
        s = max(0.0, min(1.0, s))
        prev = last.get(key, 0.1)
        val = _ewma(prev, s, alpha=0.2)
        last[key] = val
        counts[key] += 1
        risk[key] = val
    return dict(risk)


def write_predictions(risk: Dict[Tuple[str,str], float], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    now = time.time()
    with open(path, 'w', encoding='utf-8') as f:
        for (tenant, entity), val in sorted(risk.items(), key=lambda x: -x[1]):
            rec = {'ts': now, 'tenant_id': tenant, 'entity': entity, 'risk': round(float(val), 4)}
            f.write(json.dumps(rec) + "\n")


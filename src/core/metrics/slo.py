"""SLO instrumentation: ingest latency & graph retrieval latency p95 tracking.

Provides helper wrappers to observe latencies. Uses Prometheus histograms if
available, else no-op. Maintains simple rolling p95 estimation via reservoir.
"""
from __future__ import annotations

import time, math
from typing import List, Callable, Any

try:  # pragma: no cover
    from prometheus_client import Histogram  # type: ignore
except Exception:  # pragma: no cover
    class Histogram:  # type: ignore
        def __init__(self,*a,**k): pass
        def labels(self,*a,**k): return self
        def observe(self,*a,**k): return None

_INGEST_HIST = Histogram('ingest_latency_seconds','Latency for event ingestion',['adapter'])
_GRAPH_RETRIEVE_HIST = Histogram('graph_retrieve_latency_seconds','Latency for HopGraph retrieval',['op'])

_RESERVOIR_INGEST: List[float] = []
_RESERVOIR_GRAPH: List[float] = []
_MAX_RESERVOIR = 5000

def _update_reservoir(res: List[float], val: float):
    if len(res) < _MAX_RESERVOIR:
        res.append(val)
    else:
        # reservoir sampling replace with fixed probability
        import random
        i = random.randint(0, len(res)-1)
        res[i] = val

def p95(values: List[float]) -> float:
    if not values:
        return 0.0
    arr = sorted(values)
    idx = int(math.ceil(0.95 * len(arr))) - 1
    idx = max(0, min(idx, len(arr)-1))
    return arr[idx]

def ingest_latency(adapter: str, fn: Callable[[], Any]):
    start = time.time();
    try:
        return fn()
    finally:
        dur = time.time() - start
        try: _INGEST_HIST.labels(adapter=adapter).observe(dur)
        except Exception: pass
        _update_reservoir(_RESERVOIR_INGEST, dur)

def graph_latency(op: str, fn: Callable[[], Any]):
    start = time.time();
    try:
        return fn()
    finally:
        dur = time.time() - start
        try: _GRAPH_RETRIEVE_HIST.labels(op=op).observe(dur)
        except Exception: pass
        _update_reservoir(_RESERVOIR_GRAPH, dur)

def current_slo_snapshot() -> dict:
    return {
        'ingest_p95': p95(list(_RESERVOIR_INGEST)),
        'graph_retrieve_p95': p95(list(_RESERVOIR_GRAPH)),
        'ingest_samples': len(_RESERVOIR_INGEST),
        'graph_samples': len(_RESERVOIR_GRAPH)
    }

__all__ = ['ingest_latency','graph_latency','current_slo_snapshot','p95']
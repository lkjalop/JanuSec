from __future__ import annotations
try:
    # Import via the API package's metrics_init to ensure we reference the same
    # prometheus client bindings and registry as the main application in tests.
    from api.metrics_init import REGISTRY  # type: ignore
    from prometheus_client import Gauge
except Exception:  # pragma: no cover
    Gauge = None  # type: ignore

wm_edges_gauge = None
wm_soft_gauge = None
wm_hard_gauge = None

inited = False

def _init():  # idempotent
    global wm_edges_gauge, wm_soft_gauge, wm_hard_gauge, inited
    if inited or Gauge is None:
        return
    try:  # pragma: no cover
        wm_edges_gauge = Gauge('hopgraph_total_edges','Total HopGraph edges (for watermarks)')  # type: ignore
        wm_soft_gauge = Gauge('hopgraph_soft_edge_watermark','Configured HopGraph soft edge watermark')  # type: ignore
        wm_hard_gauge = Gauge('hopgraph_hard_edge_watermark','Configured HopGraph hard edge watermark')  # type: ignore
        inited = True
    except Exception:
        wm_edges_gauge = wm_soft_gauge = wm_hard_gauge = None

def set_watermarks(total_edges: int, soft: int | None, hard: int | None):
    _init()
    try:
        if wm_edges_gauge:
            wm_edges_gauge.set(total_edges)
        if wm_soft_gauge:
            wm_soft_gauge.set(soft if soft is not None else 0)
        if wm_hard_gauge:
            wm_hard_gauge.set(hard if hard is not None else 0)
    except Exception:
        pass

__all__ = ['set_watermarks']

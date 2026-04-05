from fastapi import APIRouter, HTTPException, Request
import time
import os
from typing import Any

router = APIRouter(prefix='/api/v1/health')


def _get_hopgraph():
    try:
        from src.core.graph.hopgraph_lite import get_graph
        return get_graph()
    except Exception:
        try:
            from src.graph.hopgraph import GLOBAL_HOPGRAPH  # type: ignore
            return GLOBAL_HOPGRAPH
        except Exception:
            return None


@router.get('/hopgraph')
def hopgraph_health(request: Request = None) -> Any:
    """Return lightweight health/status for HopGraph.

    Fields:
      - status: ok|degraded|unavailable
      - last_snapshot_ts: unix seconds (or null)
      - node_count, edge_count
      - reconstructions_total, evictions_total
    """
    hg = _get_hopgraph()
    if not hg:
        raise HTTPException(status_code=503, detail='HopGraph not available')
    # Determine last snapshot timestamp if attribute or backend provides it
    last_snapshot = None
    try:
        if hasattr(hg, 'backend') and getattr(hg, 'backend'):
            be = getattr(hg, 'backend')
            try:
                # backend may expose last_snapshot_ts
                last_snapshot = getattr(be, 'last_snapshot_ts', None)
            except Exception:
                last_snapshot = None
        # fallback to attribute on instance
        if last_snapshot is None:
            last_snapshot = getattr(hg, 'last_snapshot_ts', None)
    except Exception:
        last_snapshot = None

    # Node/edge counts: use gauges if present, else compute from internal structures
    node_count = None
    edge_count = None
    try:
        if hasattr(hg, 'user_hosts'):
            users = len(getattr(hg, 'user_hosts', {}))
            hosts = len(getattr(hg, 'host_users', {}))
            procs = sum(len(v) for v in getattr(hg, 'user_procs', {}).values()) if getattr(hg, 'user_procs', None) is not None else 0
            node_count = users + hosts + max(0, procs)
        if hasattr(hg, 'edges_ts'):
            edge_count = len(getattr(hg, 'edges_ts', {}))
    except Exception:
        node_count = node_count or None
        edge_count = edge_count or None

    # Metrics counters: try to read prometheus registry counters if available
    reconstructions = None
    evictions = None
    try:
        from src.core.graph.hopgraph_lite import _hg_reconstructions, _hg_evictions
        try:
            # Prometheus counters may expose _value attribute or _value.get()
            if _hg_reconstructions is not None:
                reconstructions = float(getattr(_hg_reconstructions, '_value', getattr(_hg_reconstructions, 'get', lambda: None)() or 0))
        except Exception:
            reconstructions = None
        try:
            if _hg_evictions is not None:
                evictions = float(getattr(_hg_evictions, '_value', getattr(_hg_evictions, 'get', lambda: None)() or 0))
        except Exception:
            evictions = None
    except Exception:
        reconstructions = None
        evictions = None

    status = 'ok'
    try:
        # Basic degradations: no nodes or edges seen recently -> degraded
        if (node_count is not None and node_count == 0) and (edge_count is not None and edge_count == 0):
            status = 'degraded'
    except Exception:
        pass

    return {
        'status': status,
        'last_snapshot_ts': int(last_snapshot) if isinstance(last_snapshot, (int, float)) else last_snapshot,
        'node_count': node_count,
        'edge_count': edge_count,
        'reconstructions_total': reconstructions,
        'evictions_total': evictions,
    }

from __future__ import annotations

from src.api.metrics_init import ensure_metrics, _safe_counter, _safe_gauge

hopgraph_edges_total = None
hopgraph_prune_runs_total = None
hopgraph_explain_requests_total = None
hopgraph_explain_cache_hits_total = None
hopgraph_explain_cache_misses_total = None

def init():  # idempotent
    global hopgraph_edges_total, hopgraph_prune_runs_total, hopgraph_explain_requests_total
    global hopgraph_explain_cache_hits_total, hopgraph_explain_cache_misses_total
    if hopgraph_edges_total is not None:
        return
    try:
        ensure_metrics()
    except Exception:
        pass
    # Use metrics_init helpers to register into the shared REGISTRY
    hopgraph_edges_total = _safe_gauge('hopgraph_edges_total', 'Total edges currently stored')
    # Seed a sample so the family appears in /metrics under lite/test
    try:
        # Prefer labelled setter to support forwarders/stubs
        hopgraph_edges_total.labels().set(0)
    except Exception:
        try:
            hopgraph_edges_total.set(0)
        except Exception:
            pass
    hopgraph_prune_runs_total = _safe_counter('hopgraph_prune_runs_total', 'Total prune operations run')
    hopgraph_explain_requests_total = _safe_counter('hopgraph_explain_requests_total', 'Total explain_chain requests')
    hopgraph_explain_cache_hits_total = _safe_counter('hopgraph_explain_cache_hits_total', 'LRU explain cache hits')
    hopgraph_explain_cache_misses_total = _safe_counter('hopgraph_explain_cache_misses_total', 'LRU explain cache misses')

def observe_edges(count: int):
    if hopgraph_edges_total is None:
        return
    try:
        # Prefer labelled setter to ensure _dummy_samples records the sample
        hopgraph_edges_total.labels().set(count)
    except Exception:
        try:
            hopgraph_edges_total.set(count)
        except Exception:
            pass

def inc_prune():
    if hopgraph_prune_runs_total is None:
        return
    try: hopgraph_prune_runs_total.inc()
    except Exception: pass

def inc_explain():
    if hopgraph_explain_requests_total is None:
        return
    try: hopgraph_explain_requests_total.inc()
    except Exception: pass


def inc_explain_cache_hit():
    if hopgraph_explain_cache_hits_total is None:
        return
    try: hopgraph_explain_cache_hits_total.inc()
    except Exception: pass


def inc_explain_cache_miss():
    if hopgraph_explain_cache_misses_total is None:
        return
    try: hopgraph_explain_cache_misses_total.inc()
    except Exception: pass

__all__ = ['init','observe_edges','inc_prune','inc_explain','inc_explain_cache_hit','inc_explain_cache_miss']

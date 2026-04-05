"""Additional Prometheus-style metrics helpers for HopGraph explain/stitch lifecycle.

Imported lazily inside hot paths (functions return no-op objects if registry unavailable).
"""
from __future__ import annotations
try:  # type: ignore
    from core.metrics.registry import metric_counter, metric_histogram
except Exception:  # pragma: no cover
    def metric_counter(*a, **k):  # type: ignore
        class _NoOp:
            def labels(self, *la, **lk): return self
            def inc(self, *ia, **ik): return None
        return _NoOp()
    def metric_histogram(*a, **k):  # type: ignore
        class _NoOp:
            def labels(self, *la, **lk): return self
            def observe(self, *oa, **ok): return None
        return _NoOp()

EXPLAIN_EDGE_SELECTED = metric_counter('hopgraph_explain_edge_selected_total','Count of edges considered during explain','etype')
EXPLAIN_BEAM_EXPANSION = metric_counter('hopgraph_beam_expansions_total','Beam expansions where adaptive multiplier applied','adaptive')
STITCH_SUCCESS = metric_counter('hopgraph_stitch_success_total','Chains where stitching added nodes','result')
SEQUENCE_BRIDGE_APPLIED = metric_counter('hopgraph_sequence_bridge_applied_total','Incidents where bridging added nodes','applied')
DECAY_HIST = metric_histogram('hopgraph_decay_distribution','Distribution of edge age-decay factors','etype')

__all__ = [
    'EXPLAIN_EDGE_SELECTED','EXPLAIN_BEAM_EXPANSION','STITCH_SUCCESS','SEQUENCE_BRIDGE_APPLIED','DECAY_HIST'
]

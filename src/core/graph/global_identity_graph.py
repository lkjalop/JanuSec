"""Global persistent IdentityHopGraph — wraps the canonical GLOBAL_IDENTITY_GRAPH singleton.

This module is the single source of truth for agent tools and TemporalRAG that need
to query lateral-movement paths.  It exposes the SAME object that assessment_worker
Stage 5g writes to (src.core.graph.identity_hopgraph.GLOBAL_IDENTITY_GRAPH), so
edges ingested during assessment are immediately visible to agent investigations.

Persistence: the underlying IdentityHopGraph already autosaves via
src.core.graph.persistence_sqlite when that module is available.  flush_global_identity_graph()
calls that save path; if unavailable it falls back to a JSON snapshot.

Callers:
  - Stage 5g (assessment_worker) — already writes to GLOBAL_IDENTITY_GRAPH directly
  - tool_hopgraph_query (agents/tools/registry.py) — queries via get_global_identity_graph()
  - TemporalRAGProvider.retrieve_identity_context() — already uses GLOBAL_IDENTITY_GRAPH
  - router._persist_investigation_to_memory() — flushes via flush_global_identity_graph()
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_PERSIST_PATH = os.path.join(
    os.getenv('SESSION_PERSIST_DIR', 'data/sessions'),
    'global_identity_graph.json',
)


def get_global_identity_graph():
    """Return the canonical IdentityHopGraph singleton shared with the ingest pipeline.

    This is the SAME object as src.core.graph.identity_hopgraph.GLOBAL_IDENTITY_GRAPH,
    ensuring that edges written by Stage 5g are visible to agent tools without any
    cross-singleton gap.
    """
    from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH
    return GLOBAL_IDENTITY_GRAPH


def flush_global_identity_graph() -> None:
    """Flush the canonical graph to its configured persistence backend.

    Prefers the SQLite autosave path; falls back to a JSON snapshot if unavailable.
    Safe to call frequently — it is a no-op when nothing has changed.
    """
    try:
        from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH
        # Prefer the SQLite persistence that the hopgraph module manages internally
        try:
            from src.core.graph.persistence_sqlite import GLOBAL_HOPGRAPH_PERSIST
            GLOBAL_HOPGRAPH_PERSIST.save(GLOBAL_IDENTITY_GRAPH)
            logger.debug('global_identity_graph: flushed via SQLite persistence')
            return
        except Exception:
            pass
        # Fallback: JSON snapshot (works even without persistence_sqlite)
        _save_json_snapshot(GLOBAL_IDENTITY_GRAPH)
    except Exception as exc:
        logger.debug('flush_global_identity_graph failed: %s', exc)


def _save_json_snapshot(graph) -> None:
    """Best-effort JSON snapshot of the graph adjacency and high-value set."""
    try:
        import json
        adj = graph._adj
        hv = list(graph._high_value)
        data = {
            'adj': {
                node: [
                    [dst, etype, str(ts), float(weight)]
                    for (dst, etype, ts, weight) in edges
                ]
                for node, edges in adj.items()
            },
            'high_value': hv,
        }
        path = _PERSIST_PATH
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, default=str)
        os.replace(tmp, path)
        logger.debug('global_identity_graph: JSON snapshot saved (%d nodes)', len(adj))
    except Exception as exc:
        logger.debug('global_identity_graph: JSON snapshot failed: %s', exc)

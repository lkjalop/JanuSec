# HopGraph Lite (Enhanced)

This module provides a lightweight, provenance-rich heterogeneous graph for fast multi-hop explainability.

## Node Types
host, ip, process, domain, hash, certfp, ja3 (extensible).

## Edge Provenance
Each edge captures: `(src, dst, etype, timestamp, source, weight)` where `weight` defaults from `source` via `DEFAULT_SOURCE_WEIGHTS`.

## Path Scoring
Path score = average over edges of `(source_weight * age_decay)` where `age_decay = 0.5 ** (age_seconds / half_life)` (half-life default 3600s).

## APIs
- `add_edge(src,dst,etype,source,ts,attrs,weight)`
- `add_node_attr(node, **attrs)`
- `k_hops(start, k=3)`: Unweighted BFS neighborhood.
- `explain_chain(start, max_depth=4, beam_width=5, top_k=3)`: Returns scored chains with per-hop details (`age_decay`, `contrib_score`).
- `ingest_event(event, source='event')`: Maps canonical event JSON into nodes & edges.
- `prune(now=None)`: TTL-based edge pruning (set `edge_ttl_seconds`).
- `save_snapshot()` / `load_snapshot()`.

## Configuration
Environment or runtime configurable (extend in code if needed):
- `DEFAULT_SOURCE_WEIGHTS` mapping.
- `edge_ttl_seconds` (None disables).
- `max_edges_per_node` (defaults 2048).

## Explainability Output Shape
```
{
  start: "host:a",
  chains: [
    {
      score: 0.87,
      nodes: ["host:a","process:p1","domain:evil.test"],
      length: 2,
      hops: [
        {src, dst, etype, source, timestamp, weight, age_seconds, age_decay, contrib_score},
        ...
      ]
    }
  ],
  subgraph: {nodes:{...}, edges:[{src,dst,etype,ts,source,weight}, ...]}
}
```

## Usage Notes
Use `explain_chain` to drive analyst card minimal subgraphs. Feed `subgraph` directly into incident builder or reporting layer.

## Future Extensions
- Reverse path search (backtracking from suspicious node)
- Edge attribute filters / typed weighting
- Optional on-disk compaction of WAL

## Core vs Lite vs Light (Quick Compare)

| Variant | Purpose | Durability | Typical Stage | Import |
|--------|---------|------------|---------------|--------|
| Core | Production-grade graph (WAL/snapshot, provenance, explain) | Durable (WAL+JSON snapshot; optional SQLite) | Final-stage correlation, explain, reporting | `from src.core.graph.hopgraph_core import get_core_graph, GLOBAL_HOPGRAPH` |
| Lite | Early-stage cache for time-window checks (EWMA/bursts/hotspots) | In-memory window | Early pipeline (cache-level temporal) | `from src.core.graph.hopgraph_lite import HopGraphLite` |
| Light | Late-stage lightweight tracker (compat layer; slated for consolidation) | In-memory | Late pipeline lightweight tracking | `from src.core.hunt.hopgraph_light import HopGraphLight` |

Notes:
- Prefer Core or Lite for new code. Light remains for compatibility and will be gradually phased to the two-tier model.
- Core provides `add_node_attr`, `add_edge`, `explain_chain`, pruning/watermarks, and background snapshotting hooks.

"""HopGraph Light

Lightweight in-memory temporal graph used by hunt sidecar.
Goals:
- Minimal dependencies (pure Python)
- TTL based compaction to bound memory
- Node + edge attributes (dict)
- Fast subgraph extraction by time window & seed ids

Not intended for complex Cypher-style querying; just enough to surface
chains (user -> host -> process -> connection -> technique).
"""
from __future__ import annotations

import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class HGNode:
    id: str
    kind: str  # asset|user|process|conn|technique|risk
    ts: float
    attrs: dict[str, object]

@dataclass
class HGEdge:
    src: str
    dst: str
    kind: str  # lateral|exec|connects|invokes|maps|relates
    ts: float
    attrs: dict[str, object]

class HopGraphLight:
    def __init__(self, ttl_seconds: int = 86400, max_nodes: int = 200_000, max_edges: int = 400_000):
        # Deprecation notice: prefer `src/core/graph/hopgraph_lite.py` for
        # cache-level temporal checks, and `src/core/graph/hopgraph_core.py`
        # for the production-grade core. This class remains for late-stage
        # lightweight tracking compatibility and will be consolidated over time.
        self.ttl_seconds = ttl_seconds
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self._nodes: dict[str, HGNode] = {}
        self._out: dict[str, set[str]] = {}
        self._edges: list[HGEdge] = []
        self._lock = threading.Lock()

    def add_node(self, node_id: str, kind: str, attrs: dict[str, object] | None = None, ts: float | None = None):
        now = time.time() if ts is None else ts
        with self._lock:
            if node_id in self._nodes:
                # update timestamp to most recent for freshness
                n = self._nodes[node_id]
                n.ts = now
                if attrs:
                    n.attrs.update(attrs)
            else:
                self._nodes[node_id] = HGNode(node_id, kind, now, attrs or {})
            # Light pruning if size exploding
            if len(self._nodes) > self.max_nodes:
                self._compact_nodes(target=int(self.max_nodes*0.9))

    def add_edge(self, src: str, dst: str, kind: str, attrs: dict[str, object] | None = None, ts: float | None = None):
        now = time.time() if ts is None else ts
        with self._lock:
            if src not in self._nodes or dst not in self._nodes:
                # auto-create nodes with generic kind if missing
                if src not in self._nodes:
                    self._nodes[src] = HGNode(src, 'unknown', now, {})
                if dst not in self._nodes:
                    self._nodes[dst] = HGNode(dst, 'unknown', now, {})
            e = HGEdge(src, dst, kind, now, attrs or {})
            self._edges.append(e)
            self._out.setdefault(src, set()).add(dst)
            if len(self._edges) > self.max_edges:
                self._compact_edges(target=int(self.max_edges*0.9))

    def _compact_nodes(self, target: int):
        # Remove oldest nodes by timestamp until at target
        if len(self._nodes) <= target:
            return
        ordered = sorted(self._nodes.values(), key=lambda n: n.ts)
        remove = ordered[: max(0, len(self._nodes)-target) ]
        remove_ids = {n.id for n in remove}
        for nid in remove_ids:
            self._nodes.pop(nid, None)
            self._out.pop(nid, None)
        # Remove edges touching removed nodes
        self._edges = [e for e in self._edges if e.src not in remove_ids and e.dst not in remove_ids]

    def _compact_edges(self, target: int):
        if len(self._edges) <= target:
            return
        # Remove oldest edges
        self._edges.sort(key=lambda e: e.ts)
        self._edges = self._edges[-target:]
        # Rebuild adjacency
        self._out.clear()
        for e in self._edges:
            self._out.setdefault(e.src, set()).add(e.dst)

    def ttl_compact(self):
        cutoff = time.time() - self.ttl_seconds
        with self._lock:
            remove_ids = {nid for nid, n in self._nodes.items() if n.ts < cutoff}
            if remove_ids:
                for nid in remove_ids:
                    self._nodes.pop(nid, None)
                    self._out.pop(nid, None)
                self._edges = [e for e in self._edges if e.src not in remove_ids and e.dst not in remove_ids]

    def subgraph(self, seeds: Iterable[str], depth: int = 3) -> dict[str, object]:
        with self._lock:
            visited = set()
            frontier = set(seeds)
            for _ in range(depth):
                next_frontier = set()
                for nid in frontier:
                    if nid in visited:
                        continue
                    visited.add(nid)
                    for dst in self._out.get(nid, ()):  # outward only for now
                        next_frontier.add(dst)
                frontier = next_frontier
            nodes = [self._nodes[nid].__dict__ for nid in visited if nid in self._nodes]
            edges = [e.__dict__ for e in self._edges if e.src in visited and e.dst in visited]
        return {'nodes': nodes, 'edges': edges}

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                'nodes': len(self._nodes),
                'edges': len(self._edges),
                'adjacency_entries': sum(len(v) for v in self._out.values())
            }

    # --- Additive enterprise triage helpers ---
    def detect_lateral_chain(
        self,
        user_id: str,
        within_seconds: int = 3600,
        max_hops: int = 5,
        min_hosts: int = 3,
    ) -> dict[str, object]:
        """Detect user -> asset -> asset ... chains using recent edges.

        Heuristic using node kinds:
        - Seeds: edges from the user to asset nodes (any edge kind)
        - Transitions: asset->asset edges with kind in {'lateral','connects'}
        """
        now = time.time()
        with self._lock:
            nodes = dict(self._nodes)
            edges = [e for e in self._edges if (now - e.ts) <= max(0, within_seconds)]
        if user_id not in nodes:
            return {'user': user_id, 'chains': []}
        # Identify initial assets touched by user
        initial_assets: set[str] = set(
            e.dst for e in edges
            if e.src == user_id and nodes.get(e.dst, HGNode(e.dst, 'unknown', now, {})).kind in {'asset', 'host', 'machine'}
        )
        # Build asset->asset adjacency
        asset_adj: dict[str, set[str]] = {}
        for e in edges:
            src_k = nodes.get(e.src, HGNode(e.src, 'unknown', now, {})).kind
            dst_k = nodes.get(e.dst, HGNode(e.dst, 'unknown', now, {})).kind
            if src_k in {'asset', 'host', 'machine'} and dst_k in {'asset', 'host', 'machine'} and e.kind in {'lateral', 'connects', 'relates'}:
                asset_adj.setdefault(e.src, set()).add(e.dst)
        # DFS bounded
        chains: list[list[str]] = []
        for h0 in sorted(initial_assets):
            stack: list[tuple[str, list[str]]] = [(h0, [h0])]
            seen_local: set[tuple[str, ...]] = set()
            while stack:
                node, path = stack.pop()
                if len(path) >= min_hosts:
                    chains.append(path[:])
                if len(path) - 1 >= max_hops:
                    continue
                for nxt in sorted(asset_adj.get(node, ())):
                    if nxt in path:
                        continue
                    new_path = path + [nxt]
                    key = tuple(new_path)
                    if key in seen_local:
                        continue
                    seen_local.add(key)
                    stack.append((nxt, new_path))
        return {
            'user': user_id,
            'chains': chains,
            'rapid_lateral_movement': any(len(c) >= min_hosts for c in chains),
            'lookback_seconds': within_seconds,
        }

    def reconstruct_attack(
        self,
        seed: dict[str, object],
        depth: int = 3,
        within_seconds: int = 3600,
    ) -> dict[str, object]:
        """Reconstruct small attack subgraph around a seed.

        Seeds can include 'user', 'asset' (host id), 'process'.
        """
        now = time.time()
        with self._lock:
            nodes = dict(self._nodes)
            edges = [e for e in self._edges if (now - e.ts) <= max(0, within_seconds)]
        seed_nodes: list[str] = []
        if isinstance(seed.get('user'), str):
            uid = seed['user']  # type: ignore[index]
            if uid in nodes:
                seed_nodes.append(uid)
        if isinstance(seed.get('asset'), str):
            hid = seed['asset']  # type: ignore[index]
            if hid in nodes:
                seed_nodes.append(hid)
        if isinstance(seed.get('process'), str):
            pid = seed['process']  # type: ignore[index]
            if pid in nodes:
                seed_nodes.append(pid)
        if not seed_nodes:
            return {'nodes': [], 'edges': [], 'seeds': []}
        # Build forward and reverse adjacency from filtered edges
        fwd: dict[str, set[str]] = {}
        rev: dict[str, set[str]] = {}
        for e in edges:
            fwd.setdefault(e.src, set()).add(e.dst)
            rev.setdefault(e.dst, set()).add(e.src)
        visited: set[str] = set()
        frontier: list[tuple[str, int]] = [(s, 0) for s in seed_nodes]
        while frontier:
            nid, d = frontier.pop(0)
            if nid in visited:
                continue
            visited.add(nid)
            if d >= depth:
                continue
            for nb in fwd.get(nid, ()):  # forward
                if nb not in visited:
                    frontier.append((nb, d + 1))
            for nb in rev.get(nid, ()):  # backward
                if nb not in visited:
                    frontier.append((nb, d + 1))
        # Collect nodes/edges and phase annotate
        out_nodes = [nodes[nid].__dict__ for nid in visited if nid in nodes]
        out_edges: list[dict[str, object]] = []
        for e in edges:
            if e.src in visited and e.dst in visited:
                phase = 'unknown'
                if e.kind == 'exec':
                    phase = 'execution'
                elif e.kind == 'lateral' or (nodes.get(e.src, HGNode(e.src, 'unknown', now, {})).kind in {'asset','host'} and nodes.get(e.dst, HGNode(e.dst, 'unknown', now, {})).kind in {'asset','host'}):
                    phase = 'lateral'
                elif e.kind == 'connects' and nodes.get(e.dst, HGNode(e.dst, 'unknown', now, {})).kind in {'conn','ip','service'}:
                    phase = 'exfil_or_communication'
                out_edges.append({**e.__dict__, 'phase': phase})
        out_edges.sort(key=lambda x: x['ts'])  # type: ignore[index]
        tmin = out_edges[0]['ts'] if out_edges else now  # type: ignore[index]
        tmax = out_edges[-1]['ts'] if out_edges else now  # type: ignore[index]
        return {
            'seeds': seed_nodes,
            'nodes': out_nodes,
            'edges': out_edges,
            'timeline': {'start_ts': tmin, 'end_ts': tmax},
        }

    def temporal_query(
        self,
        start_ts: float,
        end_ts: float,
        node_kind: str | None = None,
        edge_kind: str | None = None,
        limit_edges: int = 5000,
    ) -> dict[str, object]:
        """Temporal filter over nodes/edges with basic aggregates.

        Optionally filter by node_kind or edge_kind.
        """
        with self._lock:
            nodes = [n.__dict__ for n in self._nodes.values() if start_ts <= n.ts <= end_ts and (node_kind is None or n.kind == node_kind)]
            edges = [e.__dict__ for e in self._edges if start_ts <= e.ts <= end_ts and (edge_kind is None or e.kind == edge_kind)]
        edges = edges[: max(0, limit_edges)]
        # Aggregate: distinct assets per user by edge scan
        user_assets: dict[str, set[str]] = {}
        for e in edges:
            src = str(e['src'])
            dst = str(e['dst'])
            if src in self._nodes and self._nodes[src].kind == 'user' and dst in self._nodes and self._nodes[dst].kind in {'asset','host','machine'}:
                user_assets.setdefault(src, set()).add(dst)
        aggregates = {'distinct_assets_per_user': {k: len(v) for k, v in user_assets.items()}, 'edge_count': len(edges), 'node_count': len(nodes)}
        return {'nodes': nodes, 'edges': edges, 'aggregates': aggregates}

# Singleton accessor (optional)
_singleton: HopGraphLight | None = None

def get_hopgraph() -> HopGraphLight:
    global _singleton
    if _singleton is None:
        _singleton = HopGraphLight()
    return _singleton

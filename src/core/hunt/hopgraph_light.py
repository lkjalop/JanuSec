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
from dataclasses import dataclass
from typing import Dict, Set, List, Tuple, Iterable, Optional
import time
import threading

@dataclass
class HGNode:
    id: str
    kind: str  # asset|user|process|conn|technique|risk
    ts: float
    attrs: Dict[str, object]

@dataclass
class HGEdge:
    src: str
    dst: str
    kind: str  # lateral|exec|connects|invokes|maps|relates
    ts: float
    attrs: Dict[str, object]

class HopGraphLight:
    def __init__(self, ttl_seconds: int = 86400, max_nodes: int = 200_000, max_edges: int = 400_000):
        self.ttl_seconds = ttl_seconds
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self._nodes: Dict[str, HGNode] = {}
        self._out: Dict[str, Set[str]] = {}
        self._edges: List[HGEdge] = []
        self._lock = threading.Lock()

    def add_node(self, node_id: str, kind: str, attrs: Optional[Dict[str, object]] = None, ts: Optional[float] = None):
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

    def add_edge(self, src: str, dst: str, kind: str, attrs: Optional[Dict[str, object]] = None, ts: Optional[float] = None):
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

    def subgraph(self, seeds: Iterable[str], depth: int = 3) -> Dict[str, object]:
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

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                'nodes': len(self._nodes),
                'edges': len(self._edges),
                'adjacency_entries': sum(len(v) for v in self._out.values())
            }

# Singleton accessor (optional)
_singleton: HopGraphLight | None = None

def get_hopgraph() -> HopGraphLight:
    global _singleton
    if _singleton is None:
        _singleton = HopGraphLight()
    return _singleton

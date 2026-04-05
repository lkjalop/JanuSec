from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Dict, List, Tuple


class CloudHopGraph:
    """Lightweight cloud resource graph for attack path analysis.

    Node format examples:
    - cloud_resource:s3://bucket
    - cloud_resource:lambda:func
    - iam:role/admin
    - principal:arn:aws:iam::123:role/app
    """

    def __init__(self, window_seconds: int = 7 * 24 * 3600, edge_cap: int = 150_000):
        self.window_seconds = window_seconds
        self.edge_cap = edge_cap
        self._adj: Dict[str, List[Tuple[str, str, float, float]]] = defaultdict(list)
        self._last_ts = time.time()

    def add_edge(self, src: str, dst: str, etype: str, weight: float = 0.5) -> None:
        self._adj[src].append((dst, str(etype), time.time(), float(weight)))
        # no aggressive prune for simplicity; cap per node if heavily used
        if len(self._adj[src]) > 4096:
            self._adj[src] = self._adj[src][-4096:]

    def ingest_resource(self, res: Dict[str, Any]) -> None:
        node = res.get('id') or res.get('arn') or res.get('name')
        n = f"cloud_resource:{node}"
        for p in (res.get('principals') or []):
            self.add_edge(str(p), n, 'iam_allows', 0.6)
        for d in (res.get('destinations') or []):
            self.add_edge(n, str(d), 'network_access', 0.5)
        if res.get('public'):  # public exposure
            self.add_edge('internet:*', n, 'public_exposure', 0.9)

    def find_paths(self, entry: str, target: str, limit: int = 10, depth: int = 8) -> List[Dict[str, Any]]:
        entry = str(entry)
        target = str(target)
        results: List[Dict[str, Any]] = []
        frontier: List[Tuple[List[str], float]] = [([entry], 0.0)]
        seen: set[Tuple[str, ...]] = set()
        while frontier and len(results) < limit:
            path, score = frontier.pop(0)
            cur = path[-1]
            if len(path) > depth:
                continue
            if cur == target:
                key = tuple(path)
                if key not in seen:
                    results.append({'path': list(path), 'risk': float(self._score_path(path))})
                    seen.add(key)
                continue
            from src.core.rules.join_helpers import _get_adj_list  # type: ignore
            adj = _get_adj_list(self._adj if callable(getattr(self,'_adj', None)) else self)
            for (dst, etype, _ts, w) in list(adj(cur))[:64]:
                if dst in path:
                    continue
                frontier.append((path + [dst], score + self._edge_boost(etype, w)))
        results.sort(key=lambda x: x['risk'], reverse=True)
        return results[:limit]

    def _edge_boost(self, etype: str, w: float) -> float:
        etype = etype.lower()
        base = 0.0
        if etype == 'public_exposure':
            base += 0.6
        if etype == 'iam_allows':
            base += 0.4
        if etype == 'network_access':
            base += 0.3
        return base + (w * 0.2)

    def _score_path(self, path: List[str]) -> float:
        score = 0.0
        from src.core.rules.join_helpers import _get_adj_list  # type: ignore
        adj = _get_adj_list(self)
        for i in range(max(0, len(path) - 1)):
            src = path[i]
            dst = path[i + 1]
            edge = next(((d, t, ts, w) for (d, t, ts, w) in adj(src) if d == dst), None)
            if edge:
                score += self._edge_boost(edge[1], edge[3])
        return score - max(0, len(path) - 2) * 0.03

    def explain_path(self, path: List[str]) -> Dict[str, Any]:
        mitre: List[str] = []
        stride: List[str] = []
        mapping_details: List[Dict[str, Any]] = []
        pasta = 'TA6'  # Attack/Exploit (coarse)
        dread = {'damage': 0.6, 'repro': 0.6, 'exploit': 0.5, 'affected': 0.7, 'discover': 0.5}
        from src.core.rules.join_helpers import _get_adj_list  # type: ignore
        adj = _get_adj_list(self)
        for i in range(max(0, len(path) - 1)):
            src = path[i]
            dst = path[i + 1]
            t = next((t for (d, t, _ts, _w) in adj(src) if d == dst), '')
            if t == 'public_exposure':
                mitre += ['T1190']  # Initial Access via exposure (approx)
                stride += ['Information Disclosure']
                mapping_details.append({'edge': 'public_exposure', 'src': src, 'dst': dst})
            if t == 'iam_allows':
                mitre += ['T1078']  # Valid Accounts (approx)
                stride += ['Elevation of Privilege']
                mapping_details.append({'edge': 'iam_allows', 'src': src, 'dst': dst})
            if t == 'network_access':
                mitre += ['T1041']  # Exfil (approx if leading to outside)
                mapping_details.append({'edge': 'network_access', 'src': src, 'dst': dst})
        return {
            'mitre': sorted(set(mitre)),
            'stride': sorted(set(stride)),
            'pasta': pasta,
            'dread': dread,
            'mapping_details': mapping_details,
        }


GLOBAL_CLOUD_GRAPH = CloudHopGraph()

# Compatibility aliases to match Identity API
def ingest_flow(ev: dict) -> None:
    # Accept either a single resource dict or event-like, normalize
    if isinstance(ev, dict) and ('id' in ev or 'arn' in ev or 'name' in ev):
        return GLOBAL_CLOUD_GRAPH.ingest_resource(ev)
    # If it's a list or other, try best-effort
    try:
        for it in ev or []:
            GLOBAL_CLOUD_GRAPH.ingest_resource(it)
    except Exception:
        pass

def find_paths(entry: str, target: str, limit: int = 10, depth: int = 8):
    return GLOBAL_CLOUD_GRAPH.find_paths(entry, target, limit=limit, depth=depth)

def explain(path: list):
    return GLOBAL_CLOUD_GRAPH.explain_path(path)

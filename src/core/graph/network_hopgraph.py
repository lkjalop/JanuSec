from __future__ import annotations

import ipaddress
import time
from collections import defaultdict
from typing import Any, Dict, List, Tuple
from src.ml.change_point import GLOBAL_CHANGE_POINT
from src.ml.seasonality import GLOBAL_SEASONALITY
from src.ml.ensemble_anomaly import GLOBAL_ENSEMBLE_ANOMALY
from src.explain.mapping import map_enrichments
from src.explain.dread_aggregator_clean import aggregate as dread_aggregate


class NetworkHopGraph:
    """Lightweight network topology/flow graph for attack path analysis.

    Node examples:
    - ip:10.0.1.50
    - subnet:10.0.1.0/24
    - route:0.0.0.0/0

    Edge types:
    - flow           (ip -> ip)
    - membership     (ip -> subnet)
    - routing        (subnet -> subnet) or (subnet -> route)
    - internet_edge  (ip -> route:0.0.0.0/0)
    """

    def __init__(self, window_seconds: int = 24 * 3600, per_node_cap: int = 4096):
        self.window_seconds = window_seconds
        self.per_node_cap = per_node_cap
        self._adj: Dict[str, List[Tuple[str, str, float, float]]] = defaultdict(list)
        self._last_ts = time.time()

    def add_edge(self, src: str, dst: str, etype: str, weight: float = 0.5) -> None:
        self._adj[src].append((dst, str(etype), time.time(), float(weight)))
        if len(self._adj[src]) > self.per_node_cap:
            self._adj[src] = self._adj[src][-self.per_node_cap:]

    def _maybe_subnet(self, ip: str) -> str | None:
        try:
            obj = ipaddress.ip_address(ip)
            # Coarse /24 for private ranges; keep simple to avoid heavy deps
            if obj.is_private:
                if isinstance(obj, ipaddress.IPv4Address):
                    net = ipaddress.ip_network(f"{ip}/24", strict=False)
                    return f"subnet:{str(net)}"
                else:
                    net6 = ipaddress.ip_network(f"{ip}/64", strict=False)
                    return f"subnet:{str(net6)}"
        except Exception:
            return None
        return None

    def ingest_flow(self, flow: Dict[str, Any]) -> None:
        """Ingest a network flow record.

        Expected fields (best-effort):
          - src (str), dst (str), port (int|str), proto (str), bytes (int)
          - optional src_subnet/dst_subnet (str)
        """
        src_ip = str(flow.get('src') or flow.get('source') or flow.get('src_ip') or '')
        dst_ip = str(flow.get('dst') or flow.get('destination') or flow.get('dst_ip') or '')
        if not src_ip or not dst_ip:
            return
        port = int(flow.get('port') or flow.get('dst_port') or flow.get('dport') or 0)
        proto = str(flow.get('proto') or flow.get('protocol') or '').lower()
        b = float(flow.get('bytes') or flow.get('size') or 0.0)
        w = 0.2 + min(0.6, (b / 1_000_000.0))  # up to +0.6 boost for large transfers
        if proto in {'dns', 'icmp'}:
            w += 0.05
        if port in (22, 3389, 445):
            w += 0.15  # sensitive lateral ports
        if port in (80, 443):
            w += 0.05
        s = f"ip:{src_ip}"
        d = f"ip:{dst_ip}"
        self.add_edge(s, d, 'flow', w)
        # compute simple per-flow ML scores for later explanation
        try:
            size_score = GLOBAL_ENSEMBLE_ANOMALY.ingest(b).get('score', 0.0)
        except Exception:
            size_score = 0.0
        try:
            seasonal = GLOBAL_SEASONALITY.ingest(b).get('resid_score', 0.0)
        except Exception:
            seasonal = 0.0
        try:
            cp = GLOBAL_CHANGE_POINT.ingest(b)
            cp_flag = bool(cp)
        except Exception:
            cp_flag = False
        # attach a tiny metadata self-edge to src for ML traceability
        try:
            self.add_edge(s, s, 'ml_meta', float(size_score))
        except Exception:
            pass
        # membership edges (either provided or inferred)
        src_sub = str(flow.get('src_subnet') or '') or self._maybe_subnet(src_ip) or ''
        dst_sub = str(flow.get('dst_subnet') or '') or self._maybe_subnet(dst_ip) or ''
        if src_sub:
            self.add_edge(s, src_sub, 'membership', 0.3)
        if dst_sub:
            self.add_edge(d, dst_sub, 'membership', 0.3)
        # model possible internet exposure if dst is public
        try:
            if ipaddress.ip_address(dst_ip).is_global:
                self.add_edge(d, 'route:0.0.0.0/0', 'internet_edge', 0.5)
        except Exception:
            pass

    def find_paths(self, entry: str, target: str, limit: int = 10, depth: int = 7) -> List[Dict[str, Any]]:
        entry = str(entry)
        target = str(target)
        results: List[Dict[str, Any]] = []
        frontier: List[Tuple[List[str], float]] = [([entry], 0.0)]
        seen: set[Tuple[str, ...]] = set()
        from src.core.rules.join_helpers import _get_adj_list  # type: ignore
        adj = _get_adj_list(getattr(self, '_adj', self))
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
            for (dst, etype, _ts, w) in list(adj(cur))[:64]:
                if dst in path:
                    continue
                frontier.append((path + [dst], score + self._edge_boost(etype, w)))
        results.sort(key=lambda x: x['risk'], reverse=True)
        return results[:limit]

    def _edge_boost(self, etype: str, w: float) -> float:
        etype = etype.lower()
        base = 0.0
        if etype == 'flow':
            base += 0.35
        if etype == 'membership':
            base += 0.1
        if etype == 'routing':
            base += 0.2
        if etype == 'internet_edge':
            base += 0.4
        return base + (w * 0.2)

    def _score_path(self, path: List[str]) -> float:
        score = 0.0
        from src.core.rules.join_helpers import _get_adj_list  # type: ignore
        adj = _get_adj_list(getattr(self, '_adj', self))
        for i in range(max(0, len(path) - 1)):
            src = path[i]
            dst = path[i + 1]
            edge = next(((d, t, ts, w) for (d, t, ts, w) in adj(src) if d == dst), None)
            if edge:
                score += self._edge_boost(edge[1], edge[3])
        return score - max(0, len(path) - 2) * 0.03

    def explain_path(self, path: List[str]) -> Dict[str, Any]:
        """Return explainable mappings for a path: MITRE/STRIDE/PASTA/DREAD and mapping details."""
        mitre: List[str] = []
        stride: List[str] = []
        mapping_details: List[Dict[str, str]] = []
        # PASTA stage coarse guess based on edges along the way
        pasta = 'TA6'  # default: Attack/Exploit
        dread = {'damage': 0.5, 'repro': 0.6, 'exploit': 0.5, 'affected': 0.6, 'discover': 0.5}
        ml_scores: Dict[str, float] = {}
        collected_cves: list[dict] = []
        from src.core.rules.join_helpers import _get_adj_list  # type: ignore
        adj = _get_adj_list(getattr(self, '_adj', self))
        for i in range(max(0, len(path) - 1)):
            src = path[i]
            dst = path[i + 1]
            t = next((t for (d, t, _ts, _w) in adj(src) if d == dst), '')
            if t == 'flow':
                # Discovery, Lateral movement, Exfil depending on direction; keep approx
                mitre += ['T1046']  # Network Service Discovery (approx)
                stride += ['Information Disclosure']
                mapping_details.append({'edge': 'flow', 'src': src, 'dst': dst})
            if t == 'internet_edge':
                mitre += ['T1041']  # Exfiltration Over C2/Network
                stride += ['Information Disclosure']
                pasta = 'TA7'  # Execution of attack objective (exfil)
                dread['damage'] = max(dread['damage'], 0.7)
                mapping_details.append({'edge': 'internet_edge', 'src': src, 'dst': dst})
            if t == 'ml_meta':
                # include a coarse ML hint for UI
                mapping_details.append({'edge': 'ml_meta', 'src': src, 'dst': dst})
                # try to surface ml score stored as weight on a self-edge
                try:
                    # find self-edge weight
                    meta_edge = next((w for (d, et, _ts, w) in self._adj.get(src, []) if d == src and et == 'ml_meta'), None)
                    if meta_edge is not None:
                        ml_scores[src] = float(meta_edge)
                except Exception:
                    pass
            if t == 'routing':
                stride += ['Tampering']
                mapping_details.append({'edge': 'routing', 'src': src, 'dst': dst})
            # attempt to fetch recent metadata on dst (best-effort) and extract sbom/cve info
            try:
                # network graph may not store rich recent edges; use adjacency recent weights as proxy
                for (nbr, et2, _ts2, w2) in list(adj(dst))[-3:]:
                    # nbr is typically a node id string; only handle dict-like metadata defensively
                    cs = None
                    try:
                        if isinstance(nbr, dict):
                            cs = nbr.get('cve_summary')
                        else:
                            # if node id, attempt to fetch node metadata from self.nodes
                            meta = self.nodes.get(nbr) if isinstance(nbr, str) else None
                            if isinstance(meta, dict):
                                cs = meta.get('cve_summary')
                    except Exception:
                        cs = None
                    if cs and isinstance(cs, list):
                        for c in cs:
                            if isinstance(c, dict) and c.get('cve'):
                                collected_cves.append(c)
            except Exception:
                pass
        try:
            # compute anomaly as average ml score if present
            if 'ml_scores' in locals() and ml_scores:
                anomaly = float(sum(ml_scores.values()) / max(1, len(ml_scores)))
            else:
                anomaly = 0.0
            inputs = {'cves': collected_cves, 'anomaly': anomaly, 'path_length': len(path)}
            dread_calc = dread_aggregate(inputs)
            dread = {**dread, **dread_calc}
        except Exception:
            dread_calc = {}

        return {
            'mitre': sorted(set(mitre)),
            'stride': sorted(set(stride)),
            'pasta': pasta,
            'dread': dread,
            'mapping_details': mapping_details,
            'ml_scores': ml_scores if 'ml_scores' in locals() else {},
            'cve_evidence': collected_cves,
        }


GLOBAL_NETWORK_GRAPH = NetworkHopGraph()

# Compatibility wrappers
def ingest_flow(ev: dict) -> None:
    # accept single flow dict or list-like
    if isinstance(ev, dict) and ('src' in ev and 'dst' in ev):
        return GLOBAL_NETWORK_GRAPH.ingest_flow(ev)
    try:
        for f in ev or []:
            GLOBAL_NETWORK_GRAPH.ingest_flow(f)
    except Exception:
        pass

def find_paths(entry: str, target: str, limit: int = 10, depth: int = 7):
    return GLOBAL_NETWORK_GRAPH.find_paths(entry, target, limit=limit, depth=depth)

def explain(path: list):
    return GLOBAL_NETWORK_GRAPH.explain_path(path)


def ingest_bgp_prefix(prefix: str, meta: dict | None = None) -> None:
    """Ingest a BGP prefix incident into the network graph.

    This creates a 'route:' node and links any existing subnet nodes to it for context.
    meta can include {'source': 'bgp_feed', 'ts': 12345, ...} and will be stored as a lightweight edge.
    """
    try:
        node = f"route:{prefix}"
        # add a routing edge from the route node to the internet root to indicate reachability
        GLOBAL_NETWORK_GRAPH.add_edge(node, 'route:0.0.0.0/0', 'routing', 0.6)
        # optionally attach metadata as a small self-edge so it can be discovered in explain
        if meta:
            GLOBAL_NETWORK_GRAPH.add_edge(node, node, 'bgp_meta', 0.1)
    except Exception:
        pass


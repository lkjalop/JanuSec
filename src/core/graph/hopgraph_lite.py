"""HopGraph-lite: ephemeral sliding window entity relationship context.

Captures relationships among (user, host, proc, ip) over a short time window to
emit context factors (burst, lateral movement candidate, sequence motifs).

This is intentionally lightweight; for scale-out, replace with dedicated graph store.
"""
from __future__ import annotations

import time
import math
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
import os
try:
    from src.api.metrics_init import ensure_metrics, _safe_gauge, _safe_counter, _safe_hist
    ensure_metrics()
    _hg_node_count = _safe_gauge('hopgraph_nodes_total','Current HopGraph-lite node count')
    _hg_edge_count = _safe_gauge('hopgraph_edges_total','Current HopGraph-lite edge count')
    _hg_ppr_latency = _safe_hist('hopgraph_ppr_latency_seconds','PPR latency seconds')
    _hg_reconstructions = _safe_counter('hopgraph_reconstructions_total','Attack reconstructions built')
    _hg_evictions = _safe_counter('hopgraph_evictions_total','Events evicted from window')
except Exception:
    _hg_node_count = None
    _hg_edge_count = None
    _hg_ppr_latency = None
    _hg_reconstructions = None
    _hg_evictions = None
try:
    from src.core.graph.persistence.sqlite_backend import SQLiteHopGraphBackend
except Exception:
    SQLiteHopGraphBackend = None


class HopGraphLite:
    def __init__(self, window_seconds: int = 900, max_events: int = 5000):
        self.window_seconds = window_seconds
        self.max_events = max_events
        self.events: deque[tuple[float, dict[str, Any]]] = deque()
        # Simple adjacency counts
        self.user_hosts: dict[str, set[str]] = defaultdict(set)
        self.host_users: dict[str, set[str]] = defaultdict(set)
        self.user_procs: dict[str, set[str]] = defaultdict(set)
        # Typed edges with light decay (auth/process/net); value is last-seen ts
        # edge key: (src_type, src_id, dst_type, dst_id) -> last_seen_ts
        self.edges_ts: dict[tuple[str, str, str, str], float] = {}
        # Pattern hit timestamps (for coarse-grained recent checks/metrics)
        self._path_hits: deque[float] = deque()
        # Visual cue annotations collected per node id (best-effort)
        self.annotations: dict[str, set[str]] = defaultdict(set)
        # Rich node/edge registries for supply-chain/binary/network overlays
        self.node_registry: dict[str, dict[str, Any]] = {}
        self.edge_registry: dict[str, dict[str, Any]] = {}
        self._preset_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        # TTL per edge type (seconds)
        self._TTL_AUTH = 72 * 3600
        self._TTL_NET = 24 * 3600
        self._TTL_PROC = 12 * 3600
        # Lightweight spiking state: (entity, channel) -> (value, last_ts)
        self._spike_state: dict[tuple[str, str], tuple[float, float]] = {}
        # Optional per-channel weights (not used in integration thresholding by default)
        self._spike_weights: dict[str, float] = {}
        # Persistence backend (optional)
        self.backend = None
        try:
            if os.getenv('HOPGRAPH_PERSISTENCE_ENABLED', 'false').lower() == 'true' and SQLiteHopGraphBackend:
                # Per-tenant DB path support
                db_path = os.getenv('HOPGRAPH_DB_PATH', './data/hopgraph.db')
                try:
                    if os.getenv('HOPGRAPH_PER_TENANT_DB','false').lower() in {'1','true','yes'}:
                        tid = os.getenv('TENANT_ID') or os.getenv('DEFAULT_TENANT') or 'default'
                        base, ext = os.path.splitext(db_path)
                        db_path = f"{base}-{tid}{ext or '.db'}"
                except Exception:
                    pass
                try:
                    # prefer absolute path to avoid surprises in tests using tmp_path
                    db_path = os.path.abspath(db_path)
                except Exception:
                    pass
                try:
                    self.backend = SQLiteHopGraphBackend(db_path)
                except Exception:
                    # fallback: try to import alternate path where backend might be duplicated
                    try:
                        from src.core.graph.persistence.sqlite_backend import SQLiteHopGraphBackend as _AltBackend
                        self.backend = _AltBackend(db_path)
                    except Exception:
                        self.backend = None
                # Load from backend into current lightweight structures
                try:
                    data = self.backend.load_graph()
                    for nid, nd in data.get('nodes', {}).items():
                        # store minimal last-seen metadata mapping into annotations if present
                        self.annotations[nid] = set(self.annotations.get(nid, set()))
                    for e in data.get('edges', []):
                        # Rehydrate edge timestamp as now for lightweight usage
                        try:
                            src = e.get('src')
                            dst = e.get('dst')
                            etype = e.get('etype')
                            key = ('host' if src and src.startswith('host:') else 'unknown', src, 'host' if dst and dst.startswith('host:') else 'unknown', dst)
                            self.edges_ts[key] = time.time()
                        except Exception:
                            continue
                except Exception:
                    pass
        except Exception:
            self.backend = None

    def ensure_backend(self):  # idempotent re-check for tests after env monkeypatch
        try:
            if self.backend is not None:
                return
            if os.getenv('HOPGRAPH_PERSISTENCE_ENABLED', 'false').lower() == 'true' and SQLiteHopGraphBackend:
                db_path = os.getenv('HOPGRAPH_DB_PATH', './data/hopgraph.db')
                try:
                    db_path = os.path.abspath(db_path)
                except Exception:
                    pass
                try:
                    self.backend = SQLiteHopGraphBackend(db_path)
                except Exception:
                    self.backend = None
        except Exception:
            pass

    def _register_node(self, node_type: str, identifier: str, *, metadata: Optional[dict[str, Any]] = None, tags: Optional[Set[str]] = None) -> None:
        if not identifier:
            return
        now = time.time()
        key = f"{node_type}:{identifier}"
        entry = self.node_registry.setdefault(key, {
            'id': key,
            'type': node_type,
            'label': identifier,
            'metadata': {},
            'tags': set(),
            'last_seen': now,
        })
        entry['last_seen'] = now
        if metadata:
            entry['metadata'].update({k: v for k, v in metadata.items() if v not in (None, '', [])})
        if tags:
            entry['tags'].update(tags)

    def _register_edge(self, src_type: str, src_id: str, dst_type: str, dst_id: str, rel_type: str, metadata: Optional[dict[str, Any]] = None) -> None:
        if not src_id or not dst_id:
            return
        now = time.time()
        src = f"{src_type}:{src_id}"
        dst = f"{dst_type}:{dst_id}"
        edge_id = f"{src}->{dst}:{rel_type}"
        entry = self.edge_registry.setdefault(edge_id, {
            'id': edge_id,
            'src': src,
            'dst': dst,
            'type': rel_type,
            'metadata': {},
            'last_seen': now,
        })
        entry['last_seen'] = now
        if metadata:
            entry['metadata'].update({k: v for k, v in metadata.items() if v not in (None, '', [])})

    def _ingest_enriched_nodes(self, event: dict[str, Any], now: float) -> None:
        # Supply-chain packages / CI stages
        package = event.get('package') or event.get('npm_package') or event.get('artifact')
        if package:
            stage = event.get('supply_chain_stage') or event.get('npm_stage') or event.get('lifecycle')
            meta = {
                'version': event.get('package_version'),
                'sbom_component': event.get('sbom_component'),
                'stage': stage,
                'repo': event.get('repo'),
            }
            tags = {'supply_chain'}
            if stage:
                tags.add(f'stage:{stage}')
            self._register_node('package', package, metadata=meta, tags=tags)
            host = event.get('host')
            if host:
                self._register_edge('package', package, 'host', host, 'deploys', {'stage': stage})
        ci_job = event.get('ci_job') or event.get('workflow')
        if ci_job:
            self._register_node('cicd', ci_job, metadata={'status': event.get('ci_status'), 'provider': event.get('ci_provider')}, tags={'supply_chain'})
            if package:
                self._register_edge('cicd', ci_job, 'package', package, 'builds', None)
        # Binary artifacts
        binary_sha = event.get('binary_sha256') or event.get('sha256') or event.get('hash')
        if binary_sha:
            meta = {
                'entropy': event.get('binary_entropy') or event.get('entropy'),
                'signed': event.get('signed'),
                'import_count': event.get('import_count'),
                'aiat_score': event.get('aiat_score'),
                'rich_header': event.get('rich_header'),
                'sbom_impact': event.get('sbom_impact'),
            }
            tags = {'binary'}
            path = event.get('file_path') or event.get('path') or ''
            if path.lower().endswith('.dll'):
                tags.add('dll')
            if event.get('signed') is False:
                tags.add('unsigned')
            if meta['entropy'] and meta['entropy'] > 7.0:
                tags.add('high_entropy')
            self._register_node('binary', binary_sha, metadata=meta, tags=tags)
            host = event.get('host')
            if host:
                self._register_edge('binary', binary_sha, 'host', host, 'executes_on', {'path': path})
            user = event.get('user')
            if user:
                self._register_edge('user', user, 'binary', binary_sha, 'launches', {'path': path})
        # Infrastructure context (BGP/ASN/MACsec)
        asn = event.get('asn')
        infra_id = None
        if asn:
            infra_id = f"asn:{asn}"
            meta = {
                'asn': asn,
                'asn_org': event.get('asn_org'),
                'asn_anomaly': event.get('asn_anomaly'),
                'bgp_prefix': event.get('bgp_prefix'),
                'macsec_state': event.get('macsec_state'),
                'ipsec_tunnel': event.get('ipsec_tunnel'),
            }
            tags = {'infrastructure'}
            if event.get('asn_anomaly'):
                tags.add('bgp_alert')
            self._register_node('infrastructure', infra_id, metadata=meta, tags=tags)
        elif event.get('infrastructure'):
            infra_id = str(event.get('infrastructure'))
            self._register_node('infrastructure', infra_id, metadata={'kind': event.get('infra_kind')}, tags={'infrastructure'})
        if infra_id:
            host = event.get('host')
            if host:
                self._register_edge('infrastructure', infra_id, 'host', host, 'routes', {'asn': event.get('asn')})
            if binary_sha:
                self._register_edge('infrastructure', infra_id, 'binary', binary_sha, 'delivers', {'asn': event.get('asn')})

    def _trim_registry(self, now: float) -> None:
        ttl = max(self.window_seconds * 4, 3600)
        stale_nodes = [nid for nid, node in self.node_registry.items() if (now - node.get('last_seen', now)) > ttl]
        for nid in stale_nodes:
            self.node_registry.pop(nid, None)
        stale_edges = [eid for eid, edge in self.edge_registry.items() if (now - edge.get('last_seen', now)) > ttl]
        for eid in stale_edges:
            self.edge_registry.pop(eid, None)
        # prune preset cache
        for key, (ts, _) in list(self._preset_cache.items()):
            if (now - ts) > 30:
                self._preset_cache.pop(key, None)

    def _evict(self, now: float):
        cutoff = now - self.window_seconds
        evicted = 0
        while self.events and self.events[0][0] < cutoff:
            _, ev = self.events.popleft()
            evicted += 1
            u = ev.get('user')
            h = ev.get('host')
            ev.get('proc')
            if u and h and h in self.user_hosts[u]:
                # Lazy eviction; full cleanup not critical in lite version
                pass
        if len(self.events) > self.max_events:
            for _ in range(len(self.events) - self.max_events):
                self.events.popleft()
                evicted += 1
        # Remove stale edges per-type TTL
        try:
            to_del = []
            for key, ts in self.edges_ts.items():
                a_t, _a, b_t, _b = key
                ttl = self._TTL_NET
                if a_t == 'user' and b_t == 'host':  # auth
                    ttl = self._TTL_AUTH
                elif a_t == 'user' and b_t == 'proc':  # proc
                    ttl = self._TTL_PROC
                if (now - ts) > ttl:
                    to_del.append(key)
            for k in to_del:
                self.edges_ts.pop(k, None)
        except Exception:
            pass
        try:
            if _hg_evictions and evicted:
                _hg_evictions.inc(evicted)
        except Exception:
            pass

    def observe(self, event: dict[str, Any]):
        now = time.time()
        self.events.append((now, event))
        u = event.get('user')
        h = event.get('host')
        p = event.get('proc') or event.get('process')
        # Optional typed edge update (net/auth/proc) using common fields
        et = (event.get('edge_type') or '').lower()
        try:
            if et == 'net':
                src = (event.get('host') or event.get('src_host') or '')
                dst = (event.get('peer') or event.get('dest_host') or event.get('dst_host') or '')
                if src and dst:
                    self.edges_ts[('host', src, 'host', dst)] = now
            elif et == 'auth':
                usr = (event.get('user') or '')
                dst = (event.get('host') or event.get('dest_host') or '')
                if usr and dst:
                    self.edges_ts[('user', usr, 'host', dst)] = now
            elif et == 'proc':
                usr = (event.get('user') or '')
                pr = (event.get('proc') or event.get('process') or '')
                if usr and pr:
                    self.edges_ts[('user', usr, 'proc', pr)] = now
        except Exception:
            pass
        if u and h:
            self.user_hosts[u].add(h)
            self.host_users[h].add(u)
        # Persist small node/edge records if backend enabled
        try:
            if self.backend:
                # persist nodes
                if u:
                    self.backend.save_node(f'user:{u}', 'user', {'last_seen': time.time()})
                if h:
                    self.backend.save_node(f'host:{h}', 'host', {'last_seen': time.time()})
                # persist a typed edge if we set one above
                if et == 'net' and src and dst:
                    self.backend.save_edge(f'host:{src}', f'host:{dst}', 'net', metadata={'observed_at': time.time()})
                elif et == 'auth' and usr and dst:
                    self.backend.save_edge(f'user:{usr}', f'host:{dst}', 'auth', metadata={'observed_at': time.time()})
                elif et == 'proc' and usr and pr:
                    self.backend.save_edge(f'user:{usr}', f'proc:{pr}', 'proc', metadata={'observed_at': time.time()})
        except Exception:
            pass
        if u and p:
            self.user_procs[u].add(p)
        # Optional visual cues from context flags
        if event.get('context_off_hours') and h:
            self.annotations[h].add('off_hours')
        if event.get('role_sensitive') and u:
            self.annotations[u].add('role_sensitive')
        self._ingest_enriched_nodes(event, now)
        self._evict(now)
        # Update metrics gauges (best-effort)
        try:
            if _hg_edge_count:
                _hg_edge_count.set(float(len(self.edges_ts)))
            if _hg_node_count:
                # count of distinct logical nodes: users + hosts + procs seen
                users = len(self.user_hosts)
                hosts = len(self.host_users)
                procs = sum(len(v) for v in self.user_procs.values())
                _hg_node_count.set(float(users + hosts + max(0, procs)))
        except Exception:
            pass

    def factors(self, event: dict[str, Any]) -> list[str]:
        out: list[str] = []
        u = event.get('user')
        h = event.get('host')
        # Burst: multiple distinct procs for same user in window
        if u and len(self.user_procs.get(u, [])) >= 5:
            out.append('graph_user_proc_burst')
        # Lateral movement candidate: user touching >1 distinct hosts quickly
        if u and len(self.user_hosts.get(u, [])) > 1:
            out.append('lateral_movement_candidate')
        # High fan-in host (many users)
        if h and len(self.host_users.get(h, [])) > 5:
            out.append('graph_host_multiuser_hotspot')
        # Include visual cue pseudo-factors (best-effort for UI mapping)
        if h and 'off_hours' in self.annotations.get(h, set()):
            out.append('context:off_hours')
        if u and 'role_sensitive' in self.annotations.get(u, set()):
            out.append('role:user:sensitive_activity')
        # Short path template checks (best-effort; gated by recent typed edges)
        try:
            # Simple motif: (user->proc) & (user->host) within window => potential escalation path
            now = time.time()
            for (a_t, a, b_t, b), ts in list(self.edges_ts.items()):
                if now - ts > self.window_seconds:
                    continue
                if a_t == 'user' and b_t == 'proc' and u and a == u:
                    # check a recent auth from same user to some host
                    if any((k[0] == 'user' and k[1] == u and k[2] == 'host' and now - t <= self.window_seconds) for k, t in self.edges_ts.items()):
                        out.append('graph_motif_user_proc_auth')
                        self._path_hits.append(now)
                        break
            # Additional motif: auth burst -> remote tool -> DC access (approximation)
            # Detect if user authenticated to >=2 hosts recently and a proc edge includes a known remote tool,
            # and any host id looks like a domain controller (contains 'dc').
            auth_hosts = set()
            remote_tool = False
            dc_touch = False
            for (a_t, a, b_t, b), ts in list(self.edges_ts.items()):
                if now - ts > self.window_seconds:
                    continue
                if a_t == 'user' and b_t == 'host' and u and a == u:
                    auth_hosts.add(b.lower())
                    if 'dc' in (b or '').lower():
                        dc_touch = True
                if a_t == 'user' and b_t == 'proc' and u and a == u:
                    name = (b or '').lower()
                    if any(t in name for t in ('psexec','wmic','winrm','schtasks')):
                        remote_tool = True
            if len(auth_hosts) >= 2 and remote_tool and dc_touch:
                out.append('graph_motif_auth_burst_remote_tool_dc')
                self._path_hits.append(now)
            # Additional motif: same-subnet auth burst + remote tool
            def _same_subnet(x: str, y: str) -> bool:
                try:
                    # IPv4 prefix /16
                    import re
                    rx = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
                    mx = rx.match(x)
                    my = rx.match(y)
                    if mx and my:
                        return (mx.group(1), mx.group(2)) == (my.group(1), my.group(2))
                    # hostname: share domain suffix of two labels
                    xs = x.split('.')
                    ys = y.split('.')
                    return len(xs) >= 2 and len(ys) >= 2 and xs[-2:] == ys[-2:]
                except Exception:
                    return False
            same_subnet = False
            ah = list(auth_hosts)
            for i in range(len(ah)):
                for j in range(i+1, len(ah)):
                    if _same_subnet(ah[i], ah[j]):
                        same_subnet = True
                        break
                if same_subnet:
                    break
            if len(auth_hosts) >= 2 and same_subnet and remote_tool:
                out.append('graph_motif_auth_burst_remote_tool_same_subnet')
                self._path_hits.append(now)
            # Cheap HopGraph augmentations
            try:
                # Lateral velocity (hosts per 15m)
                if u:
                    vel = self.lateral_velocity(u, within_seconds=int(self.window_seconds))
                    if vel >= 5.0:
                        out.append('graph:lateral_velocity_hph')
                # Temporal motifs (auth + net wedges) and triadic DC closures
                if u:
                    motifs = self.temporal_motif_counts(u, within_seconds=int(self.window_seconds))
                    if motifs.get('auth_net_wedges', 0) >= 2:
                        out.append('graph:motif_auth_net')
                    if motifs.get('triad_dc', 0) >= 1:
                        out.append('graph:triad_dc')
                # First-touch DC (earliest auth to a DC-like node)
                if u:
                    if self._first_touch_dc(u, within_seconds=int(self.window_seconds)):
                        out.append('graph:dc_first_touch')
                # Localized PPR: seed on current user/host if present; flag if top-k includes DC
                seed: tuple[str, str] | None = None
                if isinstance(u, str) and u:
                    seed = ('user', u)
                elif isinstance(h, str) and h:
                    seed = ('host', h)
                if seed:
                    topk = self.ppr(seed, alpha=0.15, steps=8, cap=128)
                    if any(('dc' in nid.lower()) for (nt, nid, score) in topk[:5] if isinstance(nid, str)):
                        out.append('graph:ppr_topk_contains_dc')
            except Exception:
                pass
        except Exception:
            pass
        return out

    def _serialize_nodes(self, nodes: List[dict[str, Any]]) -> List[dict[str, Any]]:
        serialized: List[dict[str, Any]] = []
        for node in nodes:
            try:
                entry = {
                    'id': node.get('id'),
                    'type': node.get('type'),
                    'label': node.get('label'),
                    'metadata': dict(node.get('metadata') or {}),
                    'tags': sorted(list(node.get('tags') or [])),
                    'last_seen': node.get('last_seen'),
                }
                serialized.append(entry)
            except Exception:
                continue
        return serialized

    def _serialize_edges(self, edges: List[dict[str, Any]]) -> List[dict[str, Any]]:
        serialized: List[dict[str, Any]] = []
        for edge in edges:
            try:
                serialized.append({
                    'id': edge.get('id'),
                    'src': edge.get('src'),
                    'dst': edge.get('dst'),
                    'type': edge.get('type'),
                    'metadata': dict(edge.get('metadata') or {}),
                    'last_seen': edge.get('last_seen'),
                })
            except Exception:
                continue
        return serialized

    def snapshot(self, limit: int = 200) -> dict[str, Any]:
        nodes = sorted(self.node_registry.values(), key=lambda n: n.get('last_seen', 0), reverse=True)[:limit]
        edges = sorted(self.edge_registry.values(), key=lambda e: e.get('last_seen', 0), reverse=True)[:limit]
        return {
            'generated_ts': time.time(),
            'nodes': self._serialize_nodes(nodes),
            'edges': self._serialize_edges(edges),
            'node_count': len(self.node_registry),
            'edge_count': len(self.edge_registry),
        }

    def list_saved_queries(self) -> List[dict[str, Any]]:
        return list(_PRESET_DEFINITIONS)

    def run_saved_query(self, preset_name: str) -> dict[str, Any]:
        name = preset_name.lower()
        now = time.time()
        cached = self._preset_cache.get(name)
        if cached and (now - cached[0]) < 15:
            return cached[1]
        builder = getattr(self, f'_query_{name}', None)
        if not builder:
            raise ValueError('unknown_preset')
        payload = {
            'preset': name,
            'generated_ts': now,
            **builder(),
        }
        self._preset_cache[name] = (now, payload)
        return payload

    def _query_propagation_chain(self) -> dict[str, Any]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: List[dict[str, Any]] = []
        match_count = 0
        for node in self.node_registry.values():
            if node.get('type') not in {'package', 'cicd'}:
                continue
            outgoing = [edge for edge in self.edge_registry.values() if edge.get('src') == node.get('id') and edge.get('type') in {'deploys', 'builds'}]
            if len(outgoing) >= 2:
                match_count += 1
                nodes[node['id']] = node
                for edge in outgoing:
                    edges.append(edge)
                    dst = self.node_registry.get(edge.get('dst'))
                    if dst:
                        nodes[dst['id']] = dst
        return {
            'nodes': self._serialize_nodes(list(nodes.values())),
            'edges': self._serialize_edges(edges),
            'summary': {
                'match_count': match_count,
                'description': 'Packages or CI jobs deploying to multiple hosts within the window.',
            }
        }

    def _query_unsigned_dll_loads(self) -> dict[str, Any]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: List[dict[str, Any]] = []
        for node in self.node_registry.values():
            if node.get('type') != 'binary':
                continue
            tags = node.get('tags') or set()
            metadata = node.get('metadata') or {}
            if ('dll' in tags and 'unsigned' in tags) or metadata.get('signed') is False:
                nodes[node['id']] = node
                for edge in self.edge_registry.values():
                    if edge.get('src') == node['id'] or edge.get('dst') == node['id']:
                        edges.append(edge)
                        for nid in (edge.get('src'), edge.get('dst')):
                            other = self.node_registry.get(nid)
                            if other:
                                nodes[other['id']] = other
        return {
            'nodes': self._serialize_nodes(list(nodes.values())),
            'edges': self._serialize_edges(edges),
            'summary': {
                'match_count': len([n for n in nodes.values() if n.get('type') == 'binary']),
                'description': 'Unsigned DLL or high-entropy binaries linked to hosts/users.',
            }
        }

    def _query_bgp_malware(self) -> dict[str, Any]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: List[dict[str, Any]] = []
        matches = 0
        for node in self.node_registry.values():
            if node.get('type') != 'infrastructure':
                continue
            tags = node.get('tags') or set()
            metadata = node.get('metadata') or {}
            if 'bgp_alert' not in tags and not metadata.get('asn_anomaly'):
                continue
            connected_edges = [edge for edge in self.edge_registry.values() if edge.get('src') == node['id'] or edge.get('dst') == node['id']]
            binary_neighbors = []
            for edge in connected_edges:
                other_id = edge.get('dst') if edge.get('src') == node['id'] else edge.get('src')
                other = self.node_registry.get(other_id)
                if other and other.get('type') == 'binary':
                    meta = other.get('metadata') or {}
                    entropy = meta.get('entropy')
                    if entropy and entropy > 7.0 or 'high_entropy' in (other.get('tags') or []):
                        binary_neighbors.append(other)
            if binary_neighbors:
                matches += 1
                nodes[node['id']] = node
                for edge in connected_edges:
                    edges.append(edge)
                    for nid in (edge.get('src'), edge.get('dst')):
                        other = self.node_registry.get(nid)
                        if other:
                            nodes[other['id']] = other
        return {
            'nodes': self._serialize_nodes(list(nodes.values())),
            'edges': self._serialize_edges(edges),
            'summary': {
                'match_count': matches,
                'description': 'Infrastructure nodes with BGP/IPsec anomalies tied to suspicious binaries.',
            }
        }

    def bounded_walk(self, start: tuple[str, str], max_depth: int = 2, branch_cap: int = 20, ttl_seconds: int | None = None) -> list[tuple[str, str]]:
        """Return nodes reachable within depth using current edges, with guardrails.

        start: (type, id), e.g., ('user','alice')
        """
        try:
            now = time.time()
            ttl = ttl_seconds if ttl_seconds is not None else self.window_seconds
            # Build adjacency lazily
            adj: dict[tuple[str,str], list[tuple[str,str]]] = defaultdict(list)
            for (a_t, a, b_t, b), ts in self.edges_ts.items():
                if now - ts > ttl:
                    continue
                adj[(a_t,a)].append((b_t,b))
                # treat undirected for exploration convenience
                adj[(b_t,b)].append((a_t,a))
            seen = set()
            frontier = [(start, 0)]
            out: list[tuple[str,str]] = []
            while frontier:
                (node, depth) = frontier.pop(0)
                if node in seen:
                    continue
                seen.add(node)
                out.append(node)
                if depth >= max_depth:
                    continue
                nbrs = adj.get(node, [])[:branch_cap]
                for n in nbrs:
                    if n not in seen:
                        frontier.append((n, depth+1))
            return out
        except Exception:
            return []

    # --- Temporal / velocity helpers ---
    def temporal_motif_counts(self, user: str, within_seconds: int | None = None) -> dict[str, int]:
        """Count simple temporal motifs around a user within a lookback window.

        - auth_net_wedges: user->host (auth) and host->host (net) edges co-present
        - triad_dc: triadic closure with a DC-like node name (contains 'dc')
        """
        try:
            now = time.time()
            ttl = within_seconds if within_seconds is not None else self.window_seconds
            recent = [(k, ts) for k, ts in self.edges_ts.items() if (now - ts) <= ttl]
            auth_hosts: set[str] = set()
            net_pairs: set[tuple[str, str]] = set()
            for (a_t, a, b_t, b), ts in recent:
                if a_t == 'user' and a == user and b_t == 'host' and b:
                    auth_hosts.add(b)
                if a_t == 'host' and b_t == 'host' and a and b:
                    net_pairs.add((a, b))
            wedges = 0
            triad_dc = 0
            # For each authed host, if it has net edges to other hosts, count wedges
            for h in list(auth_hosts):
                nbrs = {b for (a, b) in net_pairs if a == h}
                if nbrs:
                    wedges += 1
                if 'dc' in h.lower() and nbrs:
                    triad_dc += 1
            return {'auth_net_wedges': wedges, 'triad_dc': triad_dc}
        except Exception:
            return {'auth_net_wedges': 0, 'triad_dc': 0}

    def lateral_velocity(self, user: str, within_seconds: int | None = None) -> float:
        """Approximate lateral hop velocity: unique hosts per 15 minutes for the user."""
        try:
            now = time.time()
            ttl = within_seconds if within_seconds is not None else max(self.window_seconds, 3600)
            # collect timestamps of user->host auths
            hits: list[float] = []
            for (a_t, a, b_t, b), ts in self.edges_ts.items():
                if a_t == 'user' and a == user and b_t == 'host' and (now - ts) <= ttl:
                    hits.append(ts)
            if not hits:
                return 0.0
            span = max(1.0, (max(hits) - min(hits)))
            # approximate unique hosts via current snapshot
            uniq_hosts = len(self.user_hosts.get(user, []))
            # normalize to 15 minutes
            per_sec = uniq_hosts / span
            return per_sec * (15 * 60)
        except Exception:
            return 0.0

    def _first_touch_dc(self, user: str, within_seconds: int | None = None) -> bool:
        try:
            now = time.time()
            ttl = within_seconds if within_seconds is not None else max(self.window_seconds, 3600)
            earliest: float | None = None
            earliest_is_dc = False
            for (a_t, a, b_t, b), ts in self.edges_ts.items():
                if a_t == 'user' and a == user and b_t == 'host' and (now - ts) <= ttl:
                    if earliest is None or ts < earliest:
                        earliest = ts
                        earliest_is_dc = isinstance(b, str) and ('dc' in b.lower())
            return bool(earliest and earliest_is_dc)
        except Exception:
            return False

    # --- Personalized PageRank over bounded subgraph ---
    def ppr(self, seed: tuple[str, str], alpha: float = 0.15, steps: int = 8, cap: int = 128) -> list[tuple[str, str, float]]:
        """Localized Personalized PageRank via short random-walk with restart.

        Returns top-N nodes as (type, id, score). Limited by steps and cap.
        """
        try:
            t0 = time.time()
            # Build adjacency (bounded by ttl and cap)
            now = time.time()
            ttl = self.window_seconds
            adj: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
            for (a_t, a, b_t, b), ts in self.edges_ts.items():
                if (now - ts) > ttl:
                    continue
                adj[(a_t, a)].append((b_t, b))
                adj[(b_t, b)].append((a_t, a))
                if len(adj) >= cap:
                    break
            # Scores
            r: dict[tuple[str, str], float] = {}
            r[seed] = 1.0
            for _ in range(max(1, steps)):
                nr: dict[tuple[str, str], float] = {}
                # restart mass
                nr[seed] = nr.get(seed, 0.0) + alpha
                one_minus = 1.0 - alpha
                for node, score in list(r.items()):
                    nbrs = adj.get(node, [])
                    if not nbrs:
                        nr[seed] = nr.get(seed, 0.0) + one_minus * score
                        continue
                    share = (one_minus * score) / len(nbrs)
                    for nb in nbrs[:16]:  # branch cap per iter
                        nr[nb] = nr.get(nb, 0.0) + share
                r = nr
            top = sorted(((t, i, s) for (t, i), s in r.items()), key=lambda x: x[2], reverse=True)
            try:
                if _hg_ppr_latency:
                    _hg_ppr_latency.observe(max(0.0, time.time()-t0))
            except Exception:
                pass
            return top[:min(len(top), 32)]
        except Exception:
            return []

    # --- Spiking integrator ---
    def integrate_spike(self, entity: str, channel: str, strength: float, decay: float = 0.5, theta: float = 1.0) -> bool:
        """Leaky integrate-and-fire per (entity, channel).

        v(t) = v0 * exp(-decay * dt) + strength; emit spike when v >= theta.
        Returns True on spike (and decays value slightly to avoid chatter).
        """
        try:
            now = time.time()
            key = (str(entity), str(channel))
            v0, ts0 = self._spike_state.get(key, (0.0, now))
            dt = max(0.0, now - ts0)
            v = v0 * math.exp(-max(0.0, float(decay)) * dt) + float(strength)
            if v >= float(theta):
                # light refractory decay
                self._spike_state[key] = (v * 0.3, now)
                return True
            self._spike_state[key] = (v, now)
            return False
        except Exception:
            return False

    def path_hit_recent(self, seconds: int = 60) -> bool:
        now = time.time()
        while self._path_hits and (now - self._path_hits[0]) > max(1, seconds):
            self._path_hits.popleft()
        return bool(self._path_hits)

    # --- Additive enterprise triage helpers ---
    def detect_lateral_chain(
        self,
        user: str,
        max_hops: int = 5,
        min_hosts: int = 3,
        within_seconds: int | None = None,
    ) -> dict[str, object]:
        """Detect multi-hop lateral movement chains for a given user.

        Heuristic: user -> host (auth), then host -> host (net) repeated.
        Returns a summary with any discovered chains of assets.
        """
        try:
            now = time.time()
            ttl = within_seconds if within_seconds is not None else 3600
            # Collect recent auth and net edges
            auth_hosts: set[str] = set()
            host_adj: dict[str, set[str]] = defaultdict(set)
            for (a_t, a, b_t, b), ts in self.edges_ts.items():
                if (now - ts) > ttl:
                    continue
                if a_t == 'user' and a == user and b_t == 'host' and b:
                    auth_hosts.add(b)
                if a_t == 'host' and b_t == 'host' and a and b:
                    host_adj[a].add(b)
            chains: list[list[str]] = []
            # Bounded DFS to enumerate unique host paths
            for h0 in sorted(auth_hosts):
                stack: list[tuple[str, list[str]]] = [(h0, [h0])]
                seen_local: set[tuple[str, ...]] = set()
                while stack:
                    node, path = stack.pop()
                    if len(path) >= min_hosts:
                        chains.append(path[:])
                        # continue exploring to find longer chains up to max_hops
                    if len(path) - 1 >= max_hops:
                        continue
                    for nxt in sorted(host_adj.get(node, ())):
                        if nxt in path:  # avoid cycles
                            continue
                        new_path = path + [nxt]
                        key = tuple(new_path)
                        if key in seen_local:
                            continue
                        seen_local.add(key)
                        stack.append((nxt, new_path))
            return {
                'user': user,
                'chains': chains,
                'rapid_lateral_movement': any(len(c) >= min_hosts for c in chains),
                'lookback_seconds': ttl,
            }
        except Exception:
            return {'user': user, 'chains': [], 'rapid_lateral_movement': False}

    def reconstruct_attack(
        self,
        seed_alert: dict[str, object],
        depth: int = 3,
        ttl_seconds: int | None = None,
    ) -> dict[str, object]:
        """Reconstruct a small attack subgraph around a seed alert.

        Walk both directions over recent typed edges and label coarse phases.
        """
        try:
            now = time.time()
            ttl = ttl_seconds if ttl_seconds is not None else max(self.window_seconds, 3600)
            # Seed nodes
            seeds: list[tuple[str, str]] = []
            u = str(seed_alert.get('user') or '')
            h = str(seed_alert.get('host') or '')
            p = str(seed_alert.get('proc') or seed_alert.get('process') or '')
            if u:
                seeds.append(('user', u))
            if h:
                seeds.append(('host', h))
            if p:
                seeds.append(('proc', p))
            if not seeds:
                return {'nodes': [], 'edges': [], 'seeds': []}
            # Build directed and reverse adjacency with timestamps
            fwd: dict[tuple[str, str], list[tuple[tuple[str, str], float]]] = defaultdict(list)
            rev: dict[tuple[str, str], list[tuple[tuple[str, str], float]]] = defaultdict(list)
            recent_edges: list[tuple[tuple[str, str, str, str], float]] = []
            for key, ts in self.edges_ts.items():
                if (now - ts) > ttl:
                    continue
                (a_t, a, b_t, b) = key
                fwd[(a_t, a)].append(((b_t, b), ts))
                rev[(b_t, b)].append(((a_t, a), ts))
                recent_edges.append((key, ts))
            # Bi-directional BFS
            visited: set[tuple[str, str]] = set()
            frontier: list[tuple[tuple[str, str], int]] = [(s, 0) for s in seeds]
            while frontier:
                (node, d) = frontier.pop(0)
                if node in visited:
                    continue
                visited.add(node)
                if d >= depth:
                    continue
                for (nbr, _ts) in fwd.get(node, ()):  # forward
                    if nbr not in visited:
                        frontier.append((nbr, d + 1))
                for (nbr, _ts) in rev.get(node, ()):  # backward
                    if nbr not in visited:
                        frontier.append((nbr, d + 1))
            # Collect edges among visited and label phases
            nodes = [{'type': t, 'id': i} for (t, i) in visited]
            edges_out: list[dict[str, object]] = []
            # earliest auth timestamp to tag initial_access
            earliest_auth_ts: float | None = None
            for (a_t, a, b_t, b), ts in recent_edges:
                if (a_t, a) in visited and (b_t, b) in visited:
                    phase = 'unknown'
                    if a_t == 'user' and b_t == 'proc':
                        phase = 'execution'
                    elif a_t == 'host' and b_t == 'host':
                        phase = 'lateral'
                    elif a_t == 'user' and b_t == 'host':
                        if earliest_auth_ts is None or ts < earliest_auth_ts:
                            earliest_auth_ts = ts
                        phase = 'lateral'
                    edges_out.append({
                        'src_type': a_t, 'src_id': a,
                        'dst_type': b_t, 'dst_id': b,
                        'ts': ts, 'phase': phase,
                    })
            # After pass, re-mark the earliest user->host edge as initial_access if present
            if earliest_auth_ts is not None:
                for e in edges_out:
                    if e['src_type'] == 'user' and e['dst_type'] == 'host' and e['ts'] == earliest_auth_ts:
                        e['phase'] = 'initial_access'
                        break
            tmin = min((e['ts'] for e in edges_out), default=now)
            tmax = max((e['ts'] for e in edges_out), default=now)
            return {
                'seeds': [{'type': t, 'id': i} for (t, i) in seeds],
                'nodes': nodes,
                'edges': sorted(edges_out, key=lambda x: x['ts']),
                'timeline': {'start_ts': tmin, 'end_ts': tmax},
            }
        except Exception:
            return {'nodes': [], 'edges': [], 'seeds': []}
        finally:
            try:
                if _hg_reconstructions:
                    _hg_reconstructions.inc(1)
            except Exception:
                pass

    def temporal_query(
        self,
        start_ts: float,
        end_ts: float,
        filters: dict[str, object] | None = None,
        limit: int = 1000,
    ) -> dict[str, object]:
        """Basic temporal query over raw observed events with simple aggregates.

        filters can include keys like 'user', 'host', 'proc', 'edge_type'.
        """
        try:
            filters = filters or {}
            out_events: list[dict[str, object]] = []
            distinct_hosts_by_user: dict[str, set[str]] = defaultdict(set)
            hourly: dict[int, int] = defaultdict(int)
            for ts, ev in list(self.events):
                if ts < start_ts or ts > end_ts:
                    continue
                match = True
                for k, v in filters.items():
                    if ev.get(k) != v:
                        match = False
                        break
                if not match:
                    continue
                if len(out_events) < max(0, limit):
                    # Shallow copy to avoid exposing internals
                    out_events.append(dict(ev))
                u = ev.get('user')
                h = ev.get('host')
                if isinstance(u, str) and isinstance(h, str) and u and h:
                    distinct_hosts_by_user[u].add(h)
                try:
                    hr = time.localtime(ts).tm_hour
                    hourly[hr] += 1
                except Exception:
                    pass
            aggregates = {
                'distinct_hosts_per_user': {u: len(s) for u, s in distinct_hosts_by_user.items()},
                'hourly_activity': dict(sorted(hourly.items())),
                'total_events': sum(hourly.values()),
            }
            # Simple off-hours detector per user (0-5 and 22-23)
            off_hours_users: list[str] = []
            if distinct_hosts_by_user:
                per_user_hours: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
                for ts, ev in list(self.events):
                    if ts < start_ts or ts > end_ts:
                        continue
                    u = ev.get('user')
                    if not isinstance(u, str) or not u:
                        continue
                    try:
                        hr = time.localtime(ts).tm_hour
                        per_user_hours[u][hr] += 1
                    except Exception:
                        continue
                for u, counts in per_user_hours.items():
                    total = sum(counts.values())
                    off = sum(c for h, c in counts.items() if h in {0,1,2,3,4,5,22,23})
                    if total >= 5 and off / max(1, total) >= 0.7:
                        off_hours_users.append(u)
            return {
                'events': out_events,
                'aggregates': aggregates,
                'off_hours_users': sorted(off_hours_users),
            }
        except Exception:
            return {'events': [], 'aggregates': {}}

# Singleton or per-tenant instance can be managed externally.
_PRESET_DEFINITIONS = [
    {
        'name': 'propagation_chain',
        'title': 'Supply Chain Propagation',
        'description': 'Detect packages / CI jobs fanning out to multiple hosts within the current window.',
    },
    {
        'name': 'unsigned_dll_loads',
        'title': 'Unsigned DLL Loads',
        'description': 'Track unsigned or high-entropy DLL binaries tied to hosts and users.',
    },
    {
        'name': 'bgp_malware',
        'title': 'BGP + Malware Overlap',
        'description': 'Surface infrastructure nodes with ASN/BGP anomalies intersecting suspicious binaries.',
    },
]
_default_graph: HopGraphLite | None = None

def get_graph() -> HopGraphLite:
    global _default_graph
    if _default_graph is None:
        _default_graph = HopGraphLite()
    # Allow tests to set env vars then call get_graph() and have backend appear
    _default_graph.ensure_backend()
    return _default_graph

__all__ = ['get_graph','HopGraphLite']

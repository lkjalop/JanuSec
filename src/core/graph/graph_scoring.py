from __future__ import annotations

import logging
_log = logging.getLogger("graph_scoring")

import time
from collections import deque
from typing import Dict, List, Any

from src.core.configuration import get_scoring_config as _load_scoring_config

try:
    from src.ml.tfidf_profile import GLOBAL_TFIDF_MANAGER
except Exception:
    GLOBAL_TFIDF_MANAGER = None

try:
    from src.ml.isolation_model import GLOBAL_ISO_MODEL
except Exception:
    GLOBAL_ISO_MODEL = None

try:
    from src.core.graph.hopgraph_lite import get_graph as _get_hopgraph  # type: ignore
except Exception:
    _get_hopgraph = None  # type: ignore


DEFAULT_WEIGHTS = {
    'path': 0.25,
    'asset': 0.16,
    'iso': 0.13,
    'tfidf': 0.10,
    'ewma': 0.08,
    'mitre': 0.08,
    'recency': 0.06,
    'corr': 0.05,
    'pagerank': 0.03,
    'diversity': 0.06,  # default: diversity now influences composite
    'mapping': 0.05,    # default: mapping semantics now influences composite
}

# Allow overriding weights via shared scoring config to stay aligned with API/UI.
try:
    _cfg = _load_scoring_config()
    _weight_overrides = _cfg.get('weights', {}) if isinstance(_cfg, dict) else {}
    for key, value in _weight_overrides.items():
        if key in DEFAULT_WEIGHTS:
            try:
                DEFAULT_WEIGHTS[key] = float(value)
            except Exception:
                continue
except Exception:
    _log.debug("scoring weight override load failed", exc_info=True)


def _edge_type_weight(et: str) -> float:
    et = (et or '').lower()
    if 'priv' in et or 'escalat' in et:
        return 0.9
    if 'lateral' in et:
        return 0.8
    if 'cloud' in et or 'iam' in et:
        return 0.7
    if 'public' in et:
        return 0.9
    if 'flow' in et or 'internet' in et:
        return 0.5
    if 'network' in et:
        return 0.4
    return 0.2


def _norm01(v: float) -> float:
    try:
        return max(0.0, min(1.0, float(v)))
    except Exception:
        return 0.0


def _canonical_node_id(node: Any) -> str | None:
    if not isinstance(node, str):
        return None
    if ':' not in node:
        return None
    return node


def _graph_adjacency(graph: Any) -> dict[str, set[str]]:
    adj: dict[str, set[str]] = {}
    try:
        edge_registry = getattr(graph, 'edge_registry', {}) or {}
        for edge in edge_registry.values():
            src = edge.get('src')
            dst = edge.get('dst')
            if not src or not dst:
                continue
            adj.setdefault(str(src), set()).add(str(dst))
            adj.setdefault(str(dst), set()).add(str(src))
    except Exception:
        pass
    return adj


def _derive_graph_features(path: List[str], ts: float | None = None) -> Dict[str, Any]:
    features: Dict[str, Any] = {
        'ppr_score': 0.0,
        'distance_from_seed': 1.0,
        'fanout': 0.0,
        'motif_hits': 0.0,
        'path_support_count': 0.0,
        'freshness_window_score': 0.0,
        'graph_available': False,
    }
    if not path or _get_hopgraph is None:
        return features
    try:
        graph = _get_hopgraph()
    except Exception:
        graph = None
    if graph is None:
        return features
    features['graph_available'] = True
    node_ids = [_canonical_node_id(n) for n in path]
    node_ids = [n for n in node_ids if n]
    if not node_ids:
        return features
    seed = node_ids[0]
    try:
        seed_type, seed_value = seed.split(':', 1)
        ppr = graph.ppr((seed_type, seed_value), alpha=0.15, steps=8, cap=128)
        ppr_map = {f"{t}:{i}": float(score) for t, i, score in ppr}
        features['ppr_score'] = _norm01(max((ppr_map.get(n, 0.0) for n in node_ids), default=0.0))
    except Exception:
        pass
    try:
        adj = _graph_adjacency(graph)
        if adj:
            q: deque[tuple[str, int]] = deque([(seed, 0)])
            seen = {seed}
            dists: dict[str, int] = {seed: 0}
            while q:
                cur, depth = q.popleft()
                for nxt in adj.get(cur, set()):
                    if nxt in seen:
                        continue
                    seen.add(nxt)
                    dists[nxt] = depth + 1
                    q.append((nxt, depth + 1))
            path_dists = [dists.get(n, 4) for n in node_ids]
            avg_dist = sum(path_dists) / max(1, len(path_dists))
            features['distance_from_seed'] = _norm01(1.0 - min(1.0, avg_dist / 4.0))
            fanouts = [len(adj.get(n, set())) for n in node_ids]
            features['fanout'] = _norm01((sum(fanouts) / max(1, len(fanouts))) / 8.0)
            support = 0
            for idx in range(len(node_ids) - 1):
                a = node_ids[idx]
                b = node_ids[idx + 1]
                if b in adj.get(a, set()):
                    support += 1
            features['path_support_count'] = _norm01(support / max(1, len(node_ids) - 1))
    except Exception:
        pass
    try:
        motif_hits = 0
        if len({n.split(':', 1)[0] for n in node_ids}) >= 3:
            motif_hits += 1
        if any(n.startswith('user:') for n in node_ids) and any(n.startswith('host:') for n in node_ids):
            motif_hits += 1
        if any(n.startswith('process:') for n in node_ids) and any(n.startswith('network:') or n.startswith('ip:') for n in node_ids):
            motif_hits += 1
        features['motif_hits'] = _norm01(motif_hits / 3.0)
    except Exception:
        pass
    try:
        node_registry = getattr(graph, 'node_registry', {}) or {}
        now = time.time()
        ref_ts = float(ts) if isinstance(ts, (int, float)) else now
        freshness = []
        for node_id in node_ids:
            last_seen = (node_registry.get(node_id) or {}).get('last_seen')
            if isinstance(last_seen, (int, float)):
                age = max(0.0, ref_ts - float(last_seen))
                freshness.append(max(0.0, 1.0 - min(1.0, age / float(max(300, getattr(graph, 'window_seconds', 900) or 900)))))
        if freshness:
            features['freshness_window_score'] = _norm01(sum(freshness) / len(freshness))
    except Exception:
        pass
    return features


def compute_composite_score(path: List[str], mapping_details: List[Dict[str, Any]] | None = None, tenant: str | None = None, ts: float | None = None, graph_features: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Compute component scores and composite for a candidate path.

    Returns scoring dict with components normalized to 0..1 and composite.
    """
    start_time = time.time()
    mapping = mapping_details or []
    # Path score: average of edge-type weights
    if mapping:
        weights = [_edge_type_weight(m.get('edge') or m.get('etype') or '') for m in mapping]
        raw_path = sum(weights) / max(1, len(weights))
    else:
        # fallback: use simple heuristic based on path length
        raw_path = 0.3 + min(0.7, (len(path) - 1) * 0.12)
    path_score = _norm01(raw_path)

    # TF-IDF rarity: attempt to use GLOBAL_TFIDF_MANAGER
    rarity = 0.0
    try:
        if GLOBAL_TFIDF_MANAGER and tenant is not None:
            prof = GLOBAL_TFIDF_MANAGER.get(tenant)
            # tokens = node ids without prefix
            tokens = [str(n).split(':',1)[-1] for n in path if isinstance(n, str)]
            rarity = _norm01(prof.get_rarity_score(tokens))
    except Exception:
        rarity = 0.0

    # EWMA anomaly: placeholder 0..1 using available temporal model if present
    ewma = 0.0
    try:
        from src.ml.temporal_periodicity import GLOBAL_TEMPORAL
        if GLOBAL_TEMPORAL:
            # periodic_anomaly returns truthy float or bool
            val = GLOBAL_TEMPORAL.periodic_anomaly()
            ewma = 1.0 if val else 0.0
    except Exception:
        ewma = 0.0

    # IsolationForest scoring
    iso = 0.0
    try:
        if GLOBAL_ISO_MODEL:
            iso = _norm01(float(GLOBAL_ISO_MODEL.score([path_score, rarity])))
    except Exception:
        iso = 0.0

    # Asset criticality heuristic
    asset = 0.0
    try:
        for n in path:
            s = str(n)
            if s.startswith('role:') or 'admin' in s.lower():
                asset = max(asset, 0.95)
            if s.startswith('cloud_resource:') and ('prod' in s.lower() or 'prod' in s):
                asset = max(asset, 0.9)
            if 'db' in s.lower() or 'secret' in s.lower():
                asset = max(asset, 0.85)
    except Exception:
        asset = 0.0

    # MITRE severity: based on count of techniques
    mitre_sev = 0.0
    try:
        # higher if many techniques
        # attempt to read mapping_details for mitre tags
        mitres = set()
        for m in mapping:
            for k in ('mitre','techniques'):
                v = m.get(k)
                if isinstance(v, (list,tuple)):
                    mitres.update(v)
        # if mapping doesn't include mitre, try empty
        mitre_sev = _norm01(min(1.0, len(mitres) / 6.0))
    except Exception:
        mitre_sev = 0.0

    # recency: recent timestamp (within 24h) gets higher score
    recency = 0.0
    try:
        if ts:
            age = max(0.0, time.time() - float(ts))
            # 0..86400 -> recency 1..0
            recency = _norm01(max(0.0, 1.0 - (age / 86400.0)))
    except Exception:
        recency = 0.0

    graph_features = graph_features or _derive_graph_features(path, ts=ts)

    # Correlated support is now derived from observed graph support when available.
    corr = _norm01(float(graph_features.get('path_support_count', 0.0)))

    # Real pagerank-style influence comes from HopGraph PPR when available.
    pagerank = _norm01(float(graph_features.get('ppr_score', 0.0)))

    # Domain diversity coefficient: encourages multi-domain chains spanning identity/endpoint/network/data/email/cloud/remote/api
    diversity = 0.0
    try:
        domains = set()
        for n in path:
            if isinstance(n, str) and ':' in n:
                d = n.split(':',1)[0]
                # normalize application/api
                if d in ('app','application'): d = 'api'
                domains.add(d)
        # scale: 0..1 based on unique domains (target 6+ for high value)
        diversity = _norm01(len(domains) / 6.0)
    except Exception:
        diversity = 0.0

    components = {
        'path_score': _norm01(path_score),
        'pagerank_influence': pagerank,
        'tfidf_rarity': rarity,
        'ewma_anomaly': ewma,
        'isolation_score': iso,
        'asset_criticality': asset,
        'mitre_severity': mitre_sev,
        'recency_score': recency,
        'correlated_event_count_norm': corr,
        'domain_diversity': diversity,
        'mapping_semantics': 0.0,
    }

    # Mapping semantics weighting: richer canonical field coverage along path
    try:
        high_value = {'user','host','process','file_hash','domain'}
        present = set()
        other_bonus = 0.0
        for n in path:
            if isinstance(n, str) and ':' in n:
                prefix = n.split(':',1)[0].lower()
                # normalize some prefixes
                if prefix in ('app','application'): prefix = 'api'
                if prefix in high_value:
                    present.add(prefix)
                elif prefix in {'ip','ip_dst','role','cloud_resource','db','secret'}:
                    other_bonus += 0.02
        hv_score = len(present)/5.0
        if len(present) >= 4:
            hv_score += 0.15
        elif len(present) >= 3:
            hv_score += 0.07
        semantics_score = _norm01(hv_score + other_bonus)
        components['mapping_semantics'] = semantics_score
    except Exception:
        pass

    # Composite linear combination
    comp = 0.0
    for k,w in DEFAULT_WEIGHTS.items():
        if k == 'path': comp += w * components['path_score']
        elif k == 'asset': comp += w * components['asset_criticality']
        elif k == 'iso': comp += w * components['isolation_score']
        elif k == 'tfidf': comp += w * components['tfidf_rarity']
        elif k == 'ewma': comp += w * components['ewma_anomaly']
        elif k == 'mitre': comp += w * components['mitre_severity']
        elif k == 'recency': comp += w * components['recency_score']
        elif k == 'corr': comp += w * components['correlated_event_count_norm']
        elif k == 'pagerank': comp += w * components['pagerank_influence']
        elif k == 'diversity': comp += w * components['domain_diversity']
        elif k == 'mapping': comp += w * components['mapping_semantics']


    composite = _norm01(comp)

    # Metrics export: log key component influences for monitoring
    try:
        _log.info("composite_score: %.3f path=%.3f mapping=%.3f diversity=%.3f ewma=%.3f", composite, components['path_score'], components['mapping_semantics'], components['domain_diversity'], components['ewma_anomaly'])
    except Exception:
        pass

    result = {
        'composite': composite,
        'components': components,
        'graph_features': graph_features,
        'computed_at': time.time(),
        'latency_ms': int((time.time() - start_time) * 1000)
    }
    return result

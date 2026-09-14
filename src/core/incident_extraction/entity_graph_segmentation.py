"""Graph-cut segmentation of a cluster into coherent sub-incidents."""
from __future__ import annotations
from typing import List, Set

WEAK_LINK_THRESHOLD = 0.35

_HIGH_CONN_IPS: set[str] = {
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '168.63.129.16', '169.254.169.254',
}
_HIGH_CONN_DOMAINS: set[str] = {
    'microsoft.com', 'windowsupdate.com', 'microsoftonline.com',
    'office.com', 'google.com', 'googleapis.com',
}


def segment_entity_graph(rows: List[dict], threshold: float = WEAK_LINK_THRESHOLD) -> List[List[dict]]:
    """Split rows into connected components by entity co-occurrence.

    Returns [[rows_segment_1], [rows_segment_2], ...].
    Returns [rows] unchanged if no meaningful split is found.
    """
    try:
        import networkx as nx
    except ImportError:
        return [rows]

    G = _build_entity_graph(rows)
    if G.number_of_edges() == 0:
        return [rows]

    _normalize_edge_weights(G, len(rows))
    _remove_weak_edges(G, threshold)
    components = list(nx.connected_components(G))

    if len(components) <= 1:
        return [rows]

    return _assign_rows_to_segments(rows, components)


def _build_entity_graph(rows: List[dict]):
    import networkx as nx
    G: nx.Graph = nx.Graph()
    for row in rows:
        entities = _extract_meaningful_entities(row)
        for i, e1 in enumerate(entities):
            for e2 in entities[i + 1:]:
                if G.has_edge(e1, e2):
                    G[e1][e2]['count'] += 1
                else:
                    G.add_edge(e1, e2, count=1)
    return G


def _extract_meaningful_entities(row: dict) -> List[str]:
    ents: list[str] = []
    for field in ('user_principal_name', 'username', 'account_id'):
        v = row.get(field)
        if v:
            ents.append(f'user:{v}')
    for acc in (row.get('accounts') or []):
        if acc:
            ents.append(f'user:{acc}')
    for field in ('hostname', 'src_host', 'dst_host'):
        v = row.get(field)
        if v:
            ents.append(f'host:{v}')
    for h in (row.get('hosts') or []):
        if h:
            ents.append(f'host:{h}')
    for field in ('src_ip', 'dst_ip'):
        v = row.get(field)
        if v and not _is_high_conn_ip(str(v)):
            ents.append(f'ip:{v}')
    for field in ('dns_query', 'sni'):
        v = row.get(field)
        if v and not _is_high_conn_domain(str(v)):
            ents.append(f'domain:{v}')
    for field in ('target_app_or_resource', 'application'):
        v = row.get(field)
        if v:
            ents.append(f'app:{v}')
    return ents


def _is_high_conn_ip(ip: str) -> bool:
    if ip in _HIGH_CONN_IPS:
        return True
    if ip.startswith('10.') and (ip.endswith('.1') or ip.endswith('.254')):
        return True
    return False


def _is_high_conn_domain(domain: str) -> bool:
    return any(domain.endswith(d) for d in _HIGH_CONN_DOMAINS)


def _normalize_edge_weights(G, total_rows: int) -> None:
    for u, v in G.edges():
        G[u][v]['weight'] = G[u][v]['count'] / max(total_rows, 1)


def _remove_weak_edges(G, threshold: float) -> None:
    weak = [(u, v) for u, v in G.edges() if G[u][v]['weight'] < threshold]
    G.remove_edges_from(weak)


def _assign_rows_to_segments(rows: List[dict], components: List[Set[str]]) -> List[List[dict]]:
    segments: list[list[dict]] = [[] for _ in components]
    orphans: list[dict] = []
    for row in rows:
        row_ents = set(_extract_meaningful_entities(row))
        best_idx, best_overlap = None, 0
        for idx, comp in enumerate(components):
            overlap = len(row_ents & comp)
            if overlap > best_overlap:
                best_overlap = overlap
                best_idx = idx
        if best_idx is not None:
            segments[best_idx].append(row)
        else:
            orphans.append(row)
    non_empty = [s for s in segments if s]
    if orphans:
        non_empty.append(orphans)
    return non_empty or [rows]

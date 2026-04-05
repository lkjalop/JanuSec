"""Reusable HopGraph join helper utilities for rule authors.

These provide small, well-documented functions that encapsulate common
join patterns used by correlation rules: identity joins, process-to-file,
network-to-host, and SBOM component joins. They are intentionally
lightweight and accept either a HopGraph-like object or a graph access
 callable to remain testable in isolation.
"""
from typing import Any, Callable, Iterable, List, Optional, Tuple


def _get_adj_list(hg: Any) -> Callable[[str], Iterable[Tuple[str, str, dict]]]:
    """Return a function that yields adjacency edges for a node.

    The helper accepts either a HopGraph instance that exposes `adj`
    mapping (node -> list of (dst, etype, meta)) or a callable that when
    passed a node_id returns an iterable of adjacency tuples.
    """
    if callable(hg):
        return hg
    # duck-type: expect hg.adj mapping
    def _adj(n: str):
        return getattr(hg, 'adj', {}).get(n, [])
    return _adj


def join_identities(hg: Any, node_id: str, max_hops: int = 2) -> List[str]:
    """Return identity-like nodes reachable from `node_id` within `max_hops`.

    Purpose: Rule authors can call this to find user / principal nodes
    connected via typical identity edges (e.g., `auth`, `owns`, `logged_in`).
    The function returns a de-duplicated list of node ids.
    """
    adj = _get_adj_list(hg)
    seen = {node_id}
    frontier = [node_id]
    identities: List[str] = []
    for _depth in range(max_hops):
        nxt: List[str] = []
        for n in frontier:
            for dst, etype, meta in adj(n):
                if dst in seen:
                    continue
                seen.add(dst)
                # heuristic: identity-like edge types
                if etype in {'auth', 'user_of', 'owns', 'member_of', 'logged_in'} or dst.startswith('user:') or dst.startswith('identity:'):
                    identities.append(dst)
                nxt.append(dst)
        frontier = nxt
    return list(dict.fromkeys(identities))


def join_process_to_file(hg: Any, process_node: str) -> List[str]:
    """Return file nodes executed or written by a process node.

    Looks for edge types like `exec`, `wrote`, `dropped`, `loaded_by`.
    """
    adj = _get_adj_list(hg)
    out: List[str] = []
    for dst, etype, meta in adj(process_node):
        if etype in {'exec', 'exec_child', 'wrote', 'dropped', 'created', 'loaded_by'} or dst.startswith('file:'):
            out.append(dst)
    return list(dict.fromkeys(out))


def join_network_to_host(hg: Any, ip_node: str) -> List[str]:
    """Return host nodes associated with an IP node (e.g., resolved, bound).

    Useful for rules that map network activity back to endpoints.
    """
    adj = _get_adj_list(hg)
    hosts: List[str] = []
    for dst, etype, meta in adj(ip_node):
        if etype in {'resolved_to', 'belongs_to', 'host_of', 'bound_to'} or dst.startswith('host:'):
            hosts.append(dst)
    return list(dict.fromkeys(hosts))


def join_sbom_components(hg: Any, component_node: str, include_deps: bool = True) -> List[str]:
    """Return related SBOM component nodes (dependencies / containers).

    Finds `depends_on`, `contains`, `provided_by` edges. If `include_deps`
    is True, returns transitive dependencies one level deep.
    """
    adj = _get_adj_list(hg)
    out: List[str] = []
    deps: List[str] = []
    for dst, etype, meta in adj(component_node):
        if etype in {'depends_on', 'contains', 'provided_by'} or dst.startswith('pkg:'):
            out.append(dst)
            deps.append(dst)
    if include_deps:
        for d in deps:
            for dst, etype, meta in adj(d):
                if (etype in {'depends_on', 'contains'}) and dst not in out:
                    out.append(dst)
    return list(dict.fromkeys(out))


__all__ = ['join_identities', 'join_process_to_file', 'join_network_to_host', 'join_sbom_components']

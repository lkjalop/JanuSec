from typing import Dict, List, Any, Set

def build_dependency_graph(deps: List[Dict[str, Any]], max_depth: int = 5) -> Dict[str, Any]:
    """Build a simple transitive dependency graph.

    deps: list of {name, version, dependencies: [...]}
    Returns an adjacency mapping and a flat set of nodes.
    """
    adj = {}
    nodes: Set[str] = set()

    def _walk(node: Dict[str, Any], depth: int):
        if depth > max_depth:
            return
        name = node.get('name')
        nodes.add(name)
        children = node.get('dependencies', []) or []
        adj.setdefault(name, set())
        for c in children:
            child_name = c.get('name')
            adj[name].add(child_name)
            _walk(c, depth + 1)

    for d in deps:
        _walk(d, 0)

    # convert sets to lists for JSON
    return {'adjacency': {k: list(v) for k, v in adj.items()}, 'nodes': list(nodes)}


def detect_dependency_confusion(graph: Dict[str, Any], internal_namespaces: List[str]) -> List[Dict[str, Any]]:
    """Detect packages that may be subject to dependency confusion (internal vs public)."""
    findings = []
    nodes = graph.get('nodes', [])
    for n in nodes:
        for ns in internal_namespaces:
            if n.startswith(ns + '.'):
                # if same short name exists publicly, flag
                short = n.split('.')[-1]
                findings.append({'factor': 'supply_chain:dependency_confusion', 'package': n, 'short': short, 'score': 0.30})
    return findings


def detect_new_rare_dependencies(current_deps: List[str], prior_deps: List[str]) -> Dict[str, Any]:
    new = set(current_deps) - set(prior_deps)
    rare = [n for n in new if n.startswith('evil') or n.count('-') > 3]
    if new:
        return {'factor': 'supply_chain:new_rare_dependencies', 'count': len(new), 'new': list(new), 'rare': rare, 'score': min(0.4, 0.1 * len(new))}
    return {}

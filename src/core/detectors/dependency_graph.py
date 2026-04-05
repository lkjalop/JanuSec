from typing import Dict, List, Set, Any


def build_dependency_graph(deps: Any) -> Dict[str, List[str]]:
    """Build adjacency list from various SBOM dependency shapes.

    Supports:
    - Dict[str, Any]: { pkg: [child1, child2] } or { pkg: '->child1,child2' }
    - CycloneDX list: [ {ref: 'pkgA', dependsOn: ['pkgB','pkgC']} ]
    - SPDX relationships list: [ {from: 'pkgA', to: 'pkgB', relationshipType: 'DEPENDS_ON'} ]
    """
    graph: Dict[str, List[str]] = {}
    if isinstance(deps, dict):
        for pkg, spec in deps.items():
            children: List[str] = []
            if isinstance(spec, str) and '->' in spec:
                tail = spec.split('->', 1)[1]
                children = [s.strip() for s in tail.split(',') if s.strip()]
            elif isinstance(spec, list):
                children = [str(s).strip() for s in spec if str(s).strip()]
            elif isinstance(spec, dict):
                # e.g., {dependsOn: [...]} or {name: child}
                arr = spec.get('dependsOn') or []
                if isinstance(arr, list):
                    children = [str(s).strip() for s in arr if str(s).strip()]
            graph[pkg] = children
        return graph
    if isinstance(deps, list):
        # CycloneDX or SPDX-style
        for entry in deps:
            try:
                ref = entry.get('ref') or entry.get('from') or entry.get('source')
                dep_type = (entry.get('relationshipType') or '').upper()
                if entry.get('dependsOn') and isinstance(entry.get('dependsOn'), list):
                    graph[ref] = [str(x) for x in entry.get('dependsOn')]
                elif dep_type == 'DEPENDS_ON':
                    src = ref
                    dst = entry.get('to') or entry.get('target')
                    if src and dst:
                        graph.setdefault(src, []).append(str(dst))
            except Exception:
                continue
        return graph
    return {}


def transitive_dependencies(graph: Dict[str, List[str]], start: str) -> Set[str]:
    seen = set()
    stack = [start]
    while stack:
        cur = stack.pop()
        for c in graph.get(cur, []):
            if c not in seen:
                seen.add(c)
                stack.append(c)
    return seen


__all__ = ['build_dependency_graph', 'transitive_dependencies']

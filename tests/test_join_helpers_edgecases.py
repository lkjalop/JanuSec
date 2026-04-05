from src.core.rules.join_helpers import join_identities, join_process_to_file, join_sbom_components


def test_callable_adj_functionality():
    def adj(n):
        if n == 'host:a':
            return [('user:alice', 'auth', {}), ('proc:p1', 'runs', {})]
        if n == 'proc:p1':
            return [('file:/tmp/x', 'exec', {})]
        return []

    ids = join_identities(adj, 'host:a')
    assert 'user:alice' in ids
    files = join_process_to_file(adj, 'proc:p1')
    assert 'file:/tmp/x' in files


def test_missing_adj_key_returns_empty():
    # adjacency callable that returns empty for unknown nodes
    def adj(n):
        return []

    assert join_identities(adj, 'nope') == []
    assert join_process_to_file(adj, 'nope') == []


def test_deeper_transitive_sbom_deps():
    # component A -> B -> C
    graph = {
        'pkg:A': [('pkg:B', 'depends_on', {})],
        'pkg:B': [('pkg:C', 'depends_on', {})],
        'pkg:C': [],
    }

    def adj(n):
        return graph.get(n, [])

    out = join_sbom_components(adj, 'pkg:A', include_deps=True)
    # Should include B and C
    assert 'pkg:B' in out
    assert 'pkg:C' in out

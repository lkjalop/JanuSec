from src.core.rules.join_helpers import join_identities, join_process_to_file, join_network_to_host, join_sbom_components


class FakeGraph:
    def __init__(self, adj):
        self.adj = adj


def test_join_helpers_basic():
    # Build a tiny adjacency map: node -> list of (dst, etype, meta)
    adj = {
        'host:1': [('ip:1', 'bound_to', {}), ('user:alice', 'owns', {})],
        'ip:1': [('host:1', 'host_of', {})],
        'proc:123': [('file:/tmp/x.ps1', 'exec', {}), ('file:/tmp/y.dll', 'loaded_by', {})],
        'pkg:foo': [('pkg:bar', 'depends_on', {}), ('pkg:baz', 'contains', {})],
        'pkg:bar': [('pkg:qux', 'depends_on', {})],
        'start': [('user:alice', 'logged_in', {}), ('host:1', 'resolved_to', {})]
    }
    hg = FakeGraph(adj)

    ids = join_identities(hg, 'start', max_hops=2)
    assert 'user:alice' in ids

    files = join_process_to_file(hg, 'proc:123')
    assert 'file:/tmp/x.ps1' in files and 'file:/tmp/y.dll' in files

    hosts = join_network_to_host(hg, 'ip:1')
    assert 'host:1' in hosts

    comps = join_sbom_components(hg, 'pkg:foo')
    # Should include direct dependencies and one-level transitive
    assert 'pkg:bar' in comps and 'pkg:qux' in comps and 'pkg:baz' in comps

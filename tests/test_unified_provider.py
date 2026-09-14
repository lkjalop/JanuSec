import types
from graph.unified import UnifiedGraph, UG


class SyntheticProvider:
    def __init__(self):
        self.edges = []
        self.nodes = set()

    def add_edge(self, src, dst, etype, **kwargs):
        self.edges.append({'src': src, 'dst': dst, 'etype': etype, **kwargs})
        self.nodes.add(src)
        self.nodes.add(dst)

    def explain_chain(self, node, max_depth=4, top_k=3, beam_width=5):
        # return a simple path if node exists
        if node in self.nodes:
            return {'paths': [[node, list(self.nodes - {node})[:1]]], 'chains': [{'score': 0.5}], 'subgraph': {'edges': self.edges}}
        return {'paths': [], 'chains': [], 'subgraph': {'edges': []}}

    def k_hops(self, node, k=2):
        return {'nodes': list(self.nodes), 'edges': self.edges}


def test_ug_routing_delegates():
    sp = SyntheticProvider()
    # bind temporary provider into UG instance
    old = UG._provider
    try:
        UG._provider = types.SimpleNamespace(name='synthetic', obj=sp, weight=999)
        UG.add_edge('host:alice', 'ip:10.0.0.1', 'conn', source='test')
        assert any(e for e in sp.edges if e['src'] == 'host:alice' and e['dst'] == 'ip:10.0.0.1')
        exp = UG.explain_chain('host:alice')
        assert isinstance(exp, dict)
        hops = UG.k_hops('host:alice')
        assert 'nodes' in hops and 'edges' in hops
    finally:
        UG._provider = old

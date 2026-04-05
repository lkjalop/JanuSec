import tempfile
import os
from src.core.graph.identity_hopgraph import IdentityHopGraph


def test_identity_snapshot_roundtrip(tmp_path):
    g = IdentityHopGraph()
    # add some edges and ewma state
    g.add_edge('user:alice', 'host:vm1', 'login', 0.5)
    g._ewma['user:alice'] = {'count': 3, 'ewma': 0.2, 'mean': 0.2, 'm2': 0.01, 'boost_last': 0.0, 'residual_last': 0.0}
    g.mark_high_value('role:admin')
    path = tmp_path / 'snap.json'
    ok = g.save_snapshot(str(path))
    assert ok
    # load into new graph
    g2 = IdentityHopGraph()
    ok2 = g2.load_snapshot(str(path))
    assert ok2
    # ensure adj and ewma loaded
    assert 'user:alice' in g2._adj
    assert 'user:alice' in g2._ewma
    assert 'role:admin' in g2._high_value

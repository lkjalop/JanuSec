from __future__ import annotations

from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH
from src.core.graph.network_hopgraph import GLOBAL_NETWORK_GRAPH


def test_identity_explain_includes_ml_scores_and_dread():
    G = GLOBAL_IDENTITY_GRAPH
    # create a simple path user -> role
    G.add_edge('user:alice', 'role:admin', 'priv_escalation', 0.9)
    # attach ml_meta self-edge to user
    G.add_edge('user:alice', 'user:alice', 'ml_meta', 0.42)
    res = G.explain_path(['user:alice', 'role:admin'])
    assert 'ml_scores' in res
    assert 'dread' in res


def test_network_explain_includes_ml_scores_and_dread():
    N = GLOBAL_NETWORK_GRAPH
    N.add_edge('ip:10.0.0.5', 'ip:10.0.0.6', 'flow', 0.5)
    N.add_edge('ip:10.0.0.5', 'ip:10.0.0.5', 'ml_meta', 0.33)
    res = N.explain_path(['ip:10.0.0.5', 'ip:10.0.0.6'])
    assert 'ml_scores' in res
    assert 'dread' in res

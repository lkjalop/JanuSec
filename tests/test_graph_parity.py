from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH as IDG
from src.core.graph.cloud_hopgraph import GLOBAL_CLOUD_GRAPH as CG
from src.core.graph.network_hopgraph import GLOBAL_NETWORK_GRAPH as NG


def _assert_explain_shape(expl):
    assert isinstance(expl, dict)
    # Expect top-level keys
    for k in ('mitre','stride','pasta','dread','mapping_details'):
        assert k in expl, f"missing key {k} in explain payload"
    assert isinstance(expl['mitre'], list)
    assert isinstance(expl['stride'], list)
    assert isinstance(expl['mapping_details'], list)
    assert isinstance(expl['dread'], dict)


def test_identity_explain_shape():
    # create a simple path and explain
    g = IDG
    # craft a short path that will yield mitre/stride entries
    p = ['user:alice','host:host1']
    g.add_edge('user:alice','host:host1','lateral_login',0.6)
    expl = g.explain_path(p)
    _assert_explain_shape(expl)


def test_cloud_explain_shape():
    g = CG
    p = ['internet:*','cloud_resource:bucket1']
    g.add_edge('internet:*','cloud_resource:bucket1','public_exposure',0.9)
    expl = g.explain_path(p)
    _assert_explain_shape(expl)


def test_network_explain_shape():
    g = NG
    p = ['ip:10.0.0.1','ip:10.0.0.2']
    g.add_edge('ip:10.0.0.1','ip:10.0.0.2','flow',0.5)
    expl = g.explain_path(p)
    _assert_explain_shape(expl)

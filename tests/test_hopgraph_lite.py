import os
import time
from src.core.graph.hopgraph_lite import get_graph


def setup_function():
    # ensure fresh graph instance
    os.environ['HOPGRAPH_PERSISTENCE_ENABLED'] = 'false'


def test_ppr_latency_and_topk():
    g = get_graph()
    # seed simple edges
    g.observe({'edge_type':'auth','user':'alice','host':'host1'})
    g.observe({'edge_type':'auth','user':'alice','host':'dc01'})
    g.observe({'edge_type':'proc','user':'alice','proc':'wmic.exe'})
    topk = g.ppr(('user','alice'), alpha=0.2, steps=4)
    assert isinstance(topk, list)
    assert any(isinstance(t[2], float) for t in topk)


def test_detect_lateral_chain_minimal():
    g = get_graph()
    g.observe({'edge_type':'auth','user':'bob','host':'h1'})
    g.observe({'edge_type':'auth','user':'bob','host':'h2'})
    g.observe({'edge_type':'net','host':'h1','peer':'h2'})
    res = g.detect_lateral_chain('bob', max_hops=3, min_hosts=2)
    assert res['rapid_lateral_movement'] is True
    assert any(len(c) >= 2 for c in res['chains'])


def test_temporal_motif_counts_and_triad():
    g = get_graph()
    g.observe({'edge_type':'auth','user':'carol','host':'dc-main'})
    g.observe({'edge_type':'net','host':'dc-main','peer':'app-01'})
    motifs = g.temporal_motif_counts('carol', within_seconds=3600)
    assert motifs['auth_net_wedges'] >= 1
    assert motifs['triad_dc'] >= 0


def test_reconstruct_attack_edge_cases():
    g = get_graph()
    # Empty seed
    res_empty = g.reconstruct_attack({}, depth=2)
    assert res_empty['nodes'] == []
    # With seed
    g.observe({'edge_type':'auth','user':'dave','host':'dc-02'})
    g.observe({'edge_type':'proc','user':'dave','proc':'psexec.exe'})
    rec = g.reconstruct_attack({'user':'dave','host':'dc-02','proc':'psexec.exe'}, depth=2)
    assert isinstance(rec['nodes'], list)
    assert isinstance(rec['edges'], list)


def test_temporal_query_basic():
    g = get_graph()
    now = time.time()
    out = g.temporal_query(start_ts=now-3600, end_ts=now+10, filters={'user':'alice'})
    assert 'aggregates' in out

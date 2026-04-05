import time

from core.hunt.hopgraph_light import HopGraphLight


def test_ttl_compaction():
    g = HopGraphLight(ttl_seconds=1)
    g.add_node('n1','user', ts=time.time()-10)
    g.add_node('n2','asset')
    g.ttl_compact()
    st = g.stats()
    assert st['nodes'] == 1 and 'n2' in [n['id'] for n in g.subgraph(['n2'])['nodes']]

def test_memory_guard_nodes():
    g = HopGraphLight(max_nodes=50)
    for i in range(60):
        g.add_node(f'n{i}','unknown')
    st = g.stats()
    assert st['nodes'] <= 50
from core.graph.hopgraph_lite import get_graph


def test_hopgraph_burst_and_lateral(reset_hopgraph=None):
    g = get_graph()
    # Simulate user touching two hosts and many procs
    for i in range(7):
        g.observe({'user':'alice','host':'host1','proc':f'p{i}'})
    g.observe({'user':'alice','host':'host2','proc':'pz'})
    factors = g.factors({'user':'alice','host':'host2'})
    assert 'graph_user_proc_burst' in factors
    assert 'lateral_movement_candidate' in factors


def test_hopgraph_host_multiuser(reset_hopgraph=None):
    g = get_graph()
    for i in range(6):
        g.observe({'user':f'u{i}','host':'shared','proc':'bash'})
    factors = g.factors({'user':'u0','host':'shared'})
    assert 'graph_host_multiuser_hotspot' in factors

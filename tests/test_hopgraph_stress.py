from core.hunt.hopgraph_light import HopGraphLight


def test_hopgraph_stress_compaction():
    g = HopGraphLight(max_nodes=500, max_edges=1000)
    # Insert many nodes & edges
    for i in range(1500):
        nid1 = f'n{i}'
        g.add_node(nid1,'unknown')
        if i>0:
            g.add_edge(f'n{i-1}', nid1, 'seq')
    st = g.stats()
    assert st['nodes'] <= 500
    assert st['edges'] <= 1000
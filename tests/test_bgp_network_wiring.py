import time
from src.integrations.bgp_client import BgpClient, CLIENT
from src.core.graph import network_hopgraph


def test_bgp_wiring_load_pushes_route_nodes(tmp_path):
    # prepare a small cache file with prefixes
    p = tmp_path / "bgp.json"
    data = {'prefixes': ['203.0.113.0/24', '198.51.100.0/24'], 'ts': time.time()}
    p.write_text(__import__('json').dumps(data), encoding='utf-8')
    bc = BgpClient()
    # override persist_path to our tmp file and call _load
    bc.persist_path = p
    bc._prefixes = set()
    bc._last = 0.0
    bc._load()
    # now check that the network graph has route nodes present
    prefixes = bc.get_prefixes()
    assert '203.0.113.0/24' in prefixes
    # the network graph should have a route node edge to internet root
    # verify that ingest_bgp_prefix created a route:203.0.113.0/24 -> route:0.0.0.0/0 edge
    # find edges from the route node
    node = f"route:203.0.113.0/24"
    adj = network_hopgraph.GLOBAL_NETWORK_GRAPH._adj.get(node, [])
    assert any(dst == 'route:0.0.0.0/0' for (dst, _t, _ts, _w) in adj)

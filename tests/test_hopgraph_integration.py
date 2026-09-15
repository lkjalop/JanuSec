import pytest, time
from src.modules.network_hunter import NetworkThreatHunter
from src.graph.hopgraph import GLOBAL_HOPGRAPH
from graph.unified import UG
from src.incidents.aggregator import GLOBAL_INCIDENTS

@pytest.mark.asyncio
async def test_hopgraph_populated_and_incident(monkeypatch):
    nh = NetworkThreatHunter(config=None)
    nh.BEACON_MIN_INTERVALS = 2
    nh.BEACON_MIN_DURATION = 1
    base_ts = time.time()
    events = [
        {'event_id':'e1','ts':base_ts,'src_host':'hostZ','dst_ip':'8.8.8.8','dst_port':443},
        {'event_id':'e2','ts':base_ts+1,'src_host':'hostZ','dst_ip':'8.8.8.8','dst_port':443},
        {'event_id':'e3','ts':base_ts+2,'src_host':'hostZ','dst_ip':'8.8.8.8','dst_port':443},
    ]
    last_factors = []
    for ev in events:
        res = await nh.analyze_event(ev)
        last_factors = res['factors']
        GLOBAL_INCIDENTS.ingest(ev, last_factors)
    # Hopgraph (via unified facade) should have host and ip nodes
    sub = UG.k_hops('host:hostz', k=1)
    assert any(n.startswith('ip:8.8.8.8') for n in sub['nodes']), sub
    # Incident aggregator produced at least one incident with hostZ
    incs = GLOBAL_INCIDENTS.list_incidents()
    assert any(i['host']=='hostz' for i in incs)

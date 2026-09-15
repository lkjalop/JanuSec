import asyncio
from src.api.deep_analyze_endpoints import GeoIPStage, ThreatIntelStage, GraphStage


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_geoip_stage_counts_internal():
    stage = GeoIPStage()
    rows = [{'ip': '10.1.2.3'}, {'ip': '8.8.8.8'}, {'ip': '10.9.9.9'}]
    res = run(stage.run({'rows': rows}))
    assert res['status'] == 'done'
    assert res['result']['internal_count'] == 2


def test_threatintel_stage_detects_hash():
    stage = ThreatIntelStage()
    rows = [{'file_hash': 'deadbeef'}, {'file_hash': 'cafebabe'}, {}]
    res = run(stage.run({'rows': rows}))
    assert res['status'] == 'done'
    assert res['result']['threat_hits'] == 1


def test_graph_stage_expansion_for_admin():
    stage = GraphStage()
    rows = [{'user': 'alice'}, {'user': 'admin'}]
    res = run(stage.run({'rows': rows}))
    assert res['status'] == 'done'
    assert res['result']['expansions'] == 1

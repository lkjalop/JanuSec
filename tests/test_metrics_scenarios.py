from fastapi.testclient import TestClient

from src.api.server import DECISION_CACHE, _record_decision, app


def test_metrics_scenario_exposition():
    DECISION_CACHE.clear()
    # Seed a decision with scenario triggers
    _record_decision('evt-metrics-1','SUSPICIOUS',0.6,['dns:tunnel_suspected','net:beacon_periodic'])
    client = TestClient(app)
    # Assume /metrics is mounted by application (Prometheus ASGI / middleware in app stack)
    r = client.get('/metrics')
    assert r.status_code == 200
    text = r.text
    # Look for scenario metric name (may appear with HELP or TYPE lines)
    assert 'scenario_matches_total' in text

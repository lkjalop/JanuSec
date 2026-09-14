import pytest
from fastapi.testclient import TestClient

# We assume api.server.app is available; we will monkeypatch minimal orchestrator dependencies.
from api.server import DecisionRecord, app
from src.api import runtime_state


@pytest.fixture
def client():
    return TestClient(app)

@pytest.mark.asyncio
async def test_explain_endpoint_basic(monkeypatch):
    # Insert decision via canonical API so test is adapter-safe
    try:
        runtime_state.DECISION_CACHE.clear()
    except Exception:
        # adapter-backed stores expose clear() but be defensive
        pass
    runtime_state.cache_set('evt1', DecisionRecord(event_id='evt1', verdict='allow', confidence=0.5,
                                                   processing_time_ms=123.0, factors=['lateral_movement_candidate','dns_tunnel_pattern'],
                                                   timestamp=0.0, tenant_id=None))
    from tests._helpers import default_test_headers
    c = TestClient(app)
    headers = default_test_headers('10.10.10.9')
    r = c.get('/api/v1/decisions/evt1/explain', headers=headers)
    assert r.status_code == 200
    data = r.json()
    tags = data['mitre_stride_tags']
    assert 'mitre_TA0008' in tags
    assert 'mitre_TA0011' in tags
    assert any(f['weight_decayed'] is None for f in data['factors'])

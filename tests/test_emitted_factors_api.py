from fastapi.testclient import TestClient
from src.api.app import create_app
from src.core.factors.emission_tracker import record_emission, get_emitted
import time


def test_emitted_factors_endpoint():
    app = create_app()
    # Ensure router is mounted in lightweight test env
    try:
        from src.api.emitted_factors_endpoints import router as _efr
        try:
            app.include_router(_efr)
        except Exception:
            pass
    except Exception:
        pass
    client = TestClient(app)
    # Record a unique emission
    ts = time.time()
    record_emission('test:emitted_factor', decision_id='dec-123', node_ids=['node:a'], ts=ts)
    # Call API
    resp = client.get('/api/v1/factors/emitted')
    assert resp.status_code == 200
    data = resp.json()
    assert 'count' in data and data['count'] >= 1
    items = data.get('items', [])
    assert any(i.get('factor') == 'test:emitted_factor' for i in items)
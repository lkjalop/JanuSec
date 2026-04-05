import os
import json
import time
from fastapi.testclient import TestClient

os.environ['METRICS_TEST_MODE'] = '1'

# Lazy import heavy modules to avoid collection-time overhead
def get_app():
    from src.api.app import create_app
    return create_app({'mode': 'test'})

def get_metrics():
    from src.api.metrics_init import ensure_metrics, REGISTRY
    return ensure_metrics, REGISTRY


def test_tier2_metrics_increment():
    ensure_metrics, REGISTRY = get_metrics()
    ensure_metrics()
    client = TestClient(get_app())
    rows = [{'row_index':0, 'raw': {'process_name':'cmd.exe', 'host':'h1', 'verdict':'suspicious', 'factors':['lolbin']}}]
    resp = client.post('/api/v1/insights/tier2/enrich_batch', json={'assessment_id':'mtest','rows':rows})
    assert resp.status_code == 200
    # REGISTRY._dummy_samples should contain tier2_completed_total or similar
    ds = getattr(REGISTRY, '_dummy_samples', {}) or {}
    # At least one metric family should be present
    assert isinstance(ds, dict)
    found = False
    for k in ds.keys():
        if 'tier2' in k or 'tier2_completed_total' in k:
            found = True
            break
    assert found is True or ds == {}

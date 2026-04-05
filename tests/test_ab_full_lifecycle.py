import os
import pytest
import time
import asyncio
from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)

# If the test environment disables the database, skip this module.
if os.environ.get('DISABLE_DB'):
    pytest.skip('Database disabled by DISABLE_DB', allow_module_level=True)


def _run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_ab_full_lifecycle():
    tenant = 'e2e-tenant'
    test_id = 'e2e-shadow'
    # enable shadow test
    r = client.post('/api/v1/ab_test/enable', json={'test_id': test_id, 'name': 'e2e shadow', 'rollout_pct': 50})
    assert r.status_code == 200 and r.json().get('ok')

    # upsert a decision (async repo call)
    from repositories import decisions_repo
    class DummyDec:
        def __init__(self, event_id):
            self.event_id = event_id
            self.verdict = 'suspicious'
            self.confidence = 0.6
            self.processing_time_ms = 12.3
            self.factors = ['f1','f2']
            self.stage_timings = []
            self.custody_hash = 'h'

    event_id = f'e2e-{int(time.time()*1000)}'
    dec = DummyDec(event_id)
    _run_async(decisions_repo.upsert_decision(event_id, dec, tenant))

    # label it as false_positive via feedback endpoint so it contributes FP
    payload = {'decision_id': event_id, 'label': 'false_positive'}
    r2 = client.post('/api/v1/feedback/decision', json=payload)
    assert r2.status_code == 200 and r2.json().get('status') == 'ok'

    # run daily aggregation (use decision_labels_repo.aggregate_daily)
    from src.repositories import decision_labels_repo
    start = (time.time() - 3600)
    # use ISO dates
    today = time.strftime('%Y-%m-%d')
    agg = _run_async(decision_labels_repo.aggregate_daily(tenant, today + 'T00:00:00Z', today + 'T23:59:59Z'))
    assert isinstance(agg, list)

    # query dashboard endpoint which should include daily and ab summary
    resp = client.get('/api/v1/dashboard/fp_reduction', params={'tenant_id': tenant, 'test_id': test_id, 'start': today, 'end': today})
    assert resp.status_code == 200
    j = resp.json()
    assert j.get('ok')
    assert 'daily' in j and isinstance(j.get('daily'), list)
    assert 'ab' in j and isinstance(j.get('ab'), list)

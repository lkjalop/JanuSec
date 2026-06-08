from datetime import datetime, timedelta, date
from fastapi.testclient import TestClient
from src.api.app import app


API_HEADERS = {'x-api-key': 'devkey123'}


def seed_ab_results_via_api(client: TestClient, tenant: str, test_id: str):
    now = datetime.utcnow()
    payloads = [
        {"test_id": test_id, "tenant_id": tenant, "variant": "A", "tp": 80, "fp": 20, "fn": 10, "started_at": (now - timedelta(days=2)).isoformat(), "ended_at": (now - timedelta(days=1)).isoformat()},
        {"test_id": test_id, "tenant_id": tenant, "variant": "B", "tp": 70, "fp": 30, "fn": 15, "started_at": (now - timedelta(days=2)).isoformat(), "ended_at": (now - timedelta(days=1)).isoformat()},
    ]
    for p in payloads:
        r = client.post('/api/v1/metrics/ab_test/result', json=p, headers=API_HEADERS)
        assert r.status_code == 200


def seed_daily_series_via_api(client: TestClient, tenant: str, start_day: date):
    rows = [
        {"day": start_day, "tp": 10, "fp": 5, "fn": 2},
        {"day": start_day + timedelta(days=1), "tp": 8, "fp": 8, "fn": 3},
        {"day": start_day + timedelta(days=2), "tp": 12, "fp": 6, "fn": 4},
    ]
    for r in rows:
        payload = {"day": r["day"].isoformat(), "tenant_id": tenant, "tp": r["tp"], "fp": r["fp"], "fn": r["fn"]}
        resp = client.post('/api/v1/metrics/precision/daily', json=payload, headers=API_HEADERS)
        assert resp.status_code == 200


def test_ab_analysis_endpoint_returns_comparison():
    # Use context manager so lifespan/startup events fire and all routers are mounted
    with TestClient(app) as client:
        seed_ab_results_via_api(client, tenant='t1', test_id='t42_cmp')
        r = client.get('/api/v1/metrics/ab/analysis',
                       params={'tenant_id': 't1', 'test_id': 't42_cmp'},
                       headers=API_HEADERS)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"
        j = r.json()
        assert j['tenant_id'] == 't1'
        assert j['test_id'] == 't42_cmp'
        assert isinstance(j['stats'], list) and len(j['stats']) >= 2
        # comparison should exist and include uplift/p_value
        assert j['comparison'] is not None, f"comparison was None; stats={j.get('stats')}"
        comp = j['comparison']
        assert 'uplift' in comp and 'p_value' in comp


def test_daily_precision_endpoint_series():
    client = TestClient(app)
    tenant = 't1'
    start_day = (datetime.utcnow() - timedelta(days=3)).date()
    seed_daily_series_via_api(client, tenant, start_day)
    # Fetch using existing precision/daily GET
    r = client.get('/api/v1/metrics/precision/daily', params={
        'tenant_id': tenant,
        'start': start_day.isoformat(),
        'end': (start_day + timedelta(days=3)).isoformat(),
    }, headers=API_HEADERS)
    assert r.status_code == 200
    j = r.json()
    assert j.get('ok') is True
    rows = j.get('rows') or []
    assert len(rows) >= 3
    first = rows[0]
    assert first['tp'] == 10 and first['fp'] == 5
    assert abs(first['precision'] - (10/15)) < 1e-6

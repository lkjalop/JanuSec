from datetime import date, timedelta
from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})

client = TestClient(app)

def test_precision_recall_trend_endpoints():
    # Seed a few days via ingest_daily
    base = date.today() - timedelta(days=3)
    for i in range(3):
        d = base + timedelta(days=i)
        payload = {
            'day': d.isoformat(),
            'tenant_id': 'default',
            'tp': 10 + i,
            'fp': 5 - i if (5 - i) > 0 else 0,
            'fn': 2 + (i//2)
        }
        r = client.post('/api/v1/metrics/ingest_daily', json=payload, headers={'x-api-key':'devkey123'})
        assert r.status_code == 200
        assert r.json().get('status') == 'ok'

    # Fetch precision/recall trend
    start = base.isoformat()
    end = (base + timedelta(days=2)).isoformat()
    r = client.get(f'/api/v1/metrics/precision_recall_trend?tenant_id=default&start={start}&end={end}', headers={'x-api-key':'devkey123'})
    assert r.status_code == 200
    j = r.json()
    assert j.get('tenant_id') == 'default'
    series = j.get('series')
    assert isinstance(series, list)
    assert len(series) >= 1
    # Each item should have day, precision, recall
    first = series[0]
    assert 'day' in first
    assert 'precision' in first
    assert 'recall' in first

    # Alerts config get/update
    r = client.get('/api/v1/metrics/alerts/config', headers={'x-api-key':'devkey123'})
    assert r.status_code == 200

    upd = {
        'tenant_id': 'default',
        'route': 'global',
        'fp_rate_max': 0.2,
        'detection_rate_min': 0.6,
        'alert_enabled': True
    }
    r = client.post('/api/v1/metrics/alerts/config', json=upd, headers={'x-api-key':'devkey123'})
    assert r.status_code == 200
    j = r.json()
    assert j.get('status') == 'ok'
    assert j.get('config', {}).get('fp_rate_max') == 0.2

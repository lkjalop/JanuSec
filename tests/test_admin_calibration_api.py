from fastapi.testclient import TestClient
from src.api.app import app


def test_admin_calibration_api(monkeypatch):
    # Monkeypatch fetch to return synthetic labeled rows
    async def fake_fetch(sql, tenant_id=None):
        return [
            {'decision_id':'d1','label':'true_positive','factors':'["f1"]'},
            {'decision_id':'d2','label':'false_positive','factors':'["f2"]'},
        ]

    monkeypatch.setattr('src.db.database.fetch', fake_fetch, raising=False)
    client = TestClient(app)
    r = client.post('/api/v1/admin/calibration/run')
    assert r.status_code == 200
    j = r.json()
    assert j.get('ok') is True

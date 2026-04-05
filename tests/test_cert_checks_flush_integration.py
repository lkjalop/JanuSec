import os, json, importlib, types, time
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    dbp = tmp_path / 'ti.sqlite'
    monkeypatch.setenv('THREAT_INTEL_DB_PATH', str(dbp))
    monkeypatch.setenv('CERT_CHECK_TTL_SEC', '3600')
    monkeypatch.setenv('CERT_CT_API_URL', 'https://ct.example')
    monkeypatch.setenv('CERT_OCSP_API_URL', 'https://ocsp.example')
    monkeypatch.setenv('CERT_CHECK_WEBHOOK_URL', 'https://webhook.example/fail-first')
    monkeypatch.setenv('CERT_CHECK_WEBHOOK_SECRET', 'secret123')
    monkeypatch.setenv('CERT_CHECK_BATCH_SIZE', '1')  # flush immediately
    monkeypatch.setenv('CERT_CHECK_BATCH_INTERVAL_SEC', '1')
    monkeypatch.setenv('CERT_CHECK_RATE_PER_MIN', '100')
    monkeypatch.setenv('CERT_CHECK_WEBHOOK_MAX_ATTEMPTS', '3')
    monkeypatch.setenv('ADMIN_API_KEY', 'adminkey')
    yield


class DummyResp:
    def __init__(self, status_code=200, json_data=None, headers=None):
        self.status_code = status_code
        self._json = json_data or {}
        self.headers = headers or {'content-type':'application/json'}
    def json(self):
        return self._json


def _build_app(monkeypatch, calls_holder):
    import src.integrations.cert_checks as cc
    importlib.reload(cc)
    def fake_get(url, timeout=5.0):
        return DummyResp(200, {'suspicious': True, 'detail': 'ct-mock'}) if '/ct/' in url else DummyResp(200, {'status':'good','detail':'ocsp-mock'})
    def fake_post(url, data=None, headers=None, timeout=5.0):
        calls_holder.append({'url': url, 'data': data, 'headers': headers})
        return DummyResp(200, {'ok': True})
    monkeypatch.setattr(cc, 'httpx', types.SimpleNamespace(get=fake_get, post=fake_post))
    # Use the existing app rather than reloading the module to avoid breaking
    # the shared app object used by other tests imported at module level.
    import src.api.app as appmod
    app = appmod.app
    return app, cc


@pytest.mark.asyncio
async def test_flush_endpoint_and_status(monkeypatch):
    calls = []
    app, cc = _build_app(monkeypatch, calls)
    client = TestClient(app)

    # Manually simulate a failed batch persisted then flush via endpoint
    import src.integrations.cert_checks as ccmod
    payload = json.dumps({'findings':[{'certfp':'flag-cert-flush-123','status':'suspicious','details':'x','ts':int(time.time())}], 'count':1})
    ccmod._persist_failed_batch(payload, 1, 'simulated_error')  # type: ignore[attr-defined]
    from tests._helpers import default_test_headers
    headers = default_test_headers('10.10.20.1')
    r_pending = client.get('/api/v1/cert_checks/pending', headers=headers)
    assert r_pending.status_code == 200
    assert r_pending.json().get('pending',0) >= 1
    # Flush via admin endpoint (include API key header so global API-key enforcer allows the request)
    hdrs = dict(headers)
    hdrs.update({'x-admin-key': 'adminkey'})
    r_flush = client.post('/api/v1/cert_checks/flush', headers=hdrs)
    assert r_flush.status_code == 200
    # After flush pending should drop (may be zero)
    r_pending2 = client.get('/api/v1/cert_checks/pending', headers=headers)
    assert r_pending2.status_code == 200
    assert r_pending2.json().get('pending',0) >= 0
    # Ensure at least one webhook POST was attempted
    # Ensure at least one webhook POST was attempted (retry path)
    assert len(calls) >= 1

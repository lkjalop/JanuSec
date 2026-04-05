import json, time, os
from fastapi.testclient import TestClient
from src.api.app import app
from src.api.ingest_controller_endpoints import _get_state

client = TestClient(app)

BASIC_EVENT = {"src_ip":"1.2.3.4","dest_ip":"5.6.7.8","alert":{"signature":"Test Sig","severity":3},"proto":"http","ts": time.time()}

def test_invalid_json_error():
    r = client.post('/api/v1/ingest/suricata', data='{"incomplete"')
    assert r.status_code == 400
    body = r.json()
    assert body['detail']['error_code'] == 'invalid_json'


def test_missing_signature_error():
    os.environ['INGEST_HMAC_SECRET'] = 'testsecret'
    # send without signature
    r = client.post('/api/v1/ingest/suricata', data=json.dumps(BASIC_EVENT))
    assert r.status_code == 401
    body = r.json()
    assert body['detail']['error_code'] == 'missing_signature'


def test_invalid_signature_error():
    os.environ['INGEST_HMAC_SECRET'] = 'testsecret2'
    r = client.post('/api/v1/ingest/suricata', data=json.dumps(BASIC_EVENT), headers={'X-Signature':'deadbeef'})
    assert r.status_code == 401
    body = r.json()
    assert body['detail']['error_code'] == 'invalid_signature'


def test_timestamp_drift_error():
    os.environ['INGEST_TS_MAX_DRIFT_SECONDS'] = '1'
    # Ensure no HMAC requirement for this test
    if 'INGEST_HMAC_SECRET' in os.environ:
        del os.environ['INGEST_HMAC_SECRET']
    # Clear any persisted hmac secrets state in controller
    try:
        st = _get_state(app)
        st['hmac_secrets'].clear()
    except Exception:
        pass
    past_ts = int(time.time()) - 10
    r = client.post('/api/v1/ingest/suricata', data=json.dumps(BASIC_EVENT), headers={'X-Ts': str(past_ts)})
    # HMAC not set so no signature requirement
    assert r.status_code == 400
    body = r.json()
    assert body['detail']['error_code'] == 'timestamp_drift'


def test_rate_limit_error():
    os.environ['INGEST_RATE_CAPACITY'] = '1'
    os.environ['INGEST_RATE_REFILL_PER_SEC'] = '0'
    # First request should pass
    r1 = client.post('/api/v1/ingest/suricata', data=json.dumps(BASIC_EVENT))
    # Second immediate request should trigger 429
    r2 = client.post('/api/v1/ingest/suricata', data=json.dumps(BASIC_EVENT))
    assert r2.status_code == 429
    body = r2.json()
    assert body['detail']['error_code'] == 'rate_limited'

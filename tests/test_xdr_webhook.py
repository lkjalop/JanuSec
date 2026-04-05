import hashlib
import hmac
import json
import time

from fastapi.testclient import TestClient

from src.api.server import app

client = TestClient(app)

# Helper to sign

def sign(secret: str, body: bytes, ts: str) -> str:
    return hmac.new(secret.encode(), msg=ts.encode()+b'.'+body, digestmod=hashlib.sha256).hexdigest()

def register(integrator_id: str, secret: str):
    r = client.post(f'/api/v1/integrations/xdr/register?integrator_id={integrator_id}&secret={secret}')
    assert r.status_code == 200


def test_xdr_webhook_hmac_and_replay():
    integrator_id = 'alpha'
    secret = 'supersecretalpha123'
    register(integrator_id, secret)
    payload = {'events':[{'id':'e1','type':'process'},{'id':'e2','type':'net'}]}
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    sig = sign(secret, body, ts)
    # First request ok
    r1 = client.post('/api/v1/integrations/xdr/webhook', data=body, headers={
        'X-Integrator-ID': integrator_id,
        'X-Timestamp': ts,
        'X-Signature': sig,
        'Content-Type': 'application/json'
    })
    assert r1.status_code == 200, r1.text
    js1 = r1.json()
    assert js1['accepted'] == 2
    # Replay (same ts + sig) -> 409
    r2 = client.post('/api/v1/integrations/xdr/webhook', data=body, headers={
        'X-Integrator-ID': integrator_id,
        'X-Timestamp': ts,
        'X-Signature': sig,
        'Content-Type': 'application/json'
    })
    assert r2.status_code == 409


def test_xdr_webhook_bad_sig():
    integrator_id = 'beta'
    secret = 'supersecretbeta123'
    register(integrator_id, secret)
    payload = {'events':[]}
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    bad_sig = 'deadbeef'
    r = client.post('/api/v1/integrations/xdr/webhook', data=body, headers={
        'X-Integrator-ID': integrator_id,
        'X-Timestamp': ts,
        'X-Signature': bad_sig,
        'Content-Type': 'application/json'
    })
    assert r.status_code == 401


def test_xdr_webhook_stale_timestamp():
    integrator_id = 'gamma'
    secret = 'supersecretgamma123'
    register(integrator_id, secret)
    body = b'{}'
    # Old timestamp beyond skew
    old_ts = str(int(time.time()) - 10000)
    sig = sign(secret, body, old_ts)
    r = client.post('/api/v1/integrations/xdr/webhook', data=body, headers={
        'X-Integrator-ID': integrator_id,
        'X-Timestamp': old_ts,
        'X-Signature': sig,
        'Content-Type': 'application/json'
    })
    assert r.status_code == 401


def test_xdr_verify_challenge():
    integrator_id = 'delta'
    secret = 'supersecretdelta123'
    register(integrator_id, secret)
    challenge = 'challenge123'
    r = client.post(f'/api/v1/integrations/xdr/verify?integrator_id={integrator_id}&challenge={challenge}')
    assert r.status_code == 200
    resp = r.json()
    assert 'response' in resp
    # deterministic hmac check
    expected = hmac.new(secret.encode(), msg=challenge.encode(), digestmod=hashlib.sha256).hexdigest()
    assert resp['response'] == expected

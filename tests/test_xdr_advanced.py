import hashlib
import hmac
import json
import secrets
import time

from fastapi.testclient import TestClient

from src.api.server import app

client = TestClient(app)

def sign(secret: str, body: bytes, ts: str) -> str:
    return hmac.new(secret.encode(), msg=ts.encode()+b'.'+body, digestmod=hashlib.sha256).hexdigest()

_TEST_HDRS = {'X-Api-Key': 'testkey123'}

def register(id_: str, secret: str|None=None):
    url = f'/api/v1/integrations/xdr/register?integrator_id={id_}'
    if secret:
        url += f'&secret={secret}'
    r = client.post(url, headers=_TEST_HDRS)
    assert r.status_code == 200
    js = r.json()
    return js['secret'] if 'secret' in js else secret

def test_rotation_and_grace():
    integrator_id = 'rotor'
    s1 = register(integrator_id, 'firstsecretrotationxxxxx')
    # rotate to new secret
    r = client.post(f'/api/v1/integrations/xdr/rotate?integrator_id={integrator_id}', headers=_TEST_HDRS)
    assert r.status_code == 200
    body = json.dumps({'events':[{'id':'grace1'}]}).encode()
    ts = str(int(time.time()))
    # old secret still valid during grace
    sig_old = sign('firstsecretrotationxxxxx', body, ts)
    r_old = client.post('/api/v1/integrations/xdr/webhook', data=body, headers={
        'X-Integrator-ID': integrator_id,
        'X-Timestamp': ts,
        'X-Signature': sig_old,
        'Content-Type': 'application/json'
    })
    assert r_old.status_code == 200

def test_oversize_payload():
    integrator_id = 'biggy'
    secret = register(integrator_id, 'bigsecretrotationxxxxx')
    body = b'a' * (300_000)  # > default 262144
    ts = str(int(time.time()))
    sig = sign(secret, body, ts)
    r = client.post('/api/v1/integrations/xdr/webhook', data=body, headers={
        'X-Integrator-ID': integrator_id,
        'X-Timestamp': ts,
        'X-Signature': sig,
        'Content-Type': 'application/json'
    })
    assert r.status_code == 413 or r.status_code == 401  # 401 if obfuscated


def test_missing_headers():
    r = client.post('/api/v1/integrations/xdr/webhook', json={})
    assert r.status_code in (400,401)  # may be obfuscated


def test_unknown_integrator():
    body = b'{}'
    ts = str(int(time.time()))
    sig = 'deadbeef'
    r = client.post('/api/v1/integrations/xdr/webhook', data=body, headers={
        'X-Timestamp': ts,
        'X-Signature': sig,
        'Content-Type': 'application/json'
    })
    # unknown integrator (missing id) -> missing headers or unauthorized
    assert r.status_code in (400,401)


def test_rate_limiting():
    integrator_id = 'ratelimit'
    secret = register(integrator_id, 'ratesecretrotationxxxxx')
    body = json.dumps({'events':[]}).encode()
    ts = str(int(time.time()))
    sig = sign(secret, body, ts)
    # Burst more than bucket capacity quickly
    exceeded = False
    for i in range(0, 120):
        ts = str(int(time.time()))
        sig = sign(secret, body, ts)
        r = client.post('/api/v1/integrations/xdr/webhook', data=body, headers={
            'X-Integrator-ID': integrator_id,
            'X-Timestamp': ts,
            'X-Signature': sig,
            'Content-Type': 'application/json'
        })
        if r.status_code == 429:
            exceeded = True
            break
    assert exceeded

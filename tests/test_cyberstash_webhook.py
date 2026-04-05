import hashlib
import hmac
import json
import os
import time

from fastapi.testclient import TestClient

from src.api.app import app


def make_sig(secret: str, body: bytes, ts: int) -> str:
    mac = hmac.new(secret.encode('utf-8'), msg=str(ts).encode('utf-8') + b'.' + body, digestmod=hashlib.sha256)
    return mac.hexdigest()


def test_cyberstash_webhook_hmac_and_replay(monkeypatch):
    monkeypatch.setenv('CYBERSTASH_WEBHOOK_SECRET', 's3cr3t-cs')
    client = TestClient(app)
    body = json.dumps({'alert': 'suspicious'}).encode()
    ts = int(time.time())
    sig = make_sig('s3cr3t-cs', body, ts)

    # First request should be accepted
    r1 = client.post('/api/v1/integrations/cyberstash/webhook', data=body, headers={'X-Timestamp': str(ts), 'X-Signature': sig, 'Content-Type': 'application/json'})
    assert r1.status_code in (200, 201, 202)
    js = r1.json()
    assert js.get('accepted') is True or js.get('queued') is True

    # Replay with same ts/signature should be blocked
    r2 = client.post('/api/v1/integrations/cyberstash/webhook', data=body, headers={'X-Timestamp': str(ts), 'X-Signature': sig, 'Content-Type': 'application/json'})
    assert r2.status_code == 409


def test_cyberstash_webhook_bad_sig(monkeypatch):
    monkeypatch.setenv('CYBERSTASH_WEBHOOK_SECRET', 'anothersecret')
    client = TestClient(app)
    body = b'{}'
    ts = int(time.time())
    bad_sig = '00deadbeef'
    r = client.post('/api/v1/integrations/cyberstash/webhook', data=body, headers={'X-Timestamp': str(ts), 'X-Signature': bad_sig, 'Content-Type': 'application/json'})
    assert r.status_code == 401


def test_cyberstash_webhook_stale_timestamp(monkeypatch):
    monkeypatch.setenv('CYBERSTASH_WEBHOOK_SECRET', 'yetsecret')
    client = TestClient(app)
    body = b'{}'
    old_ts = int(time.time()) - 999999
    sig = make_sig('yetsecret', body, old_ts)
    r = client.post('/api/v1/integrations/cyberstash/webhook', data=body, headers={'X-Timestamp': str(old_ts), 'X-Signature': sig, 'Content-Type': 'application/json'})
    assert r.status_code == 401

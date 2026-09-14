import hashlib
import sys
import types
import hmac
import json
import time
from starlette.testclient import TestClient

from src.api.app import create_app
app = create_app({'mode': 'test'})

# Ensure optional DB driver doesn't break test collection in lite mode
if 'psycopg2' not in sys.modules:
    sys.modules['psycopg2'] = types.ModuleType('psycopg2')


def make_sig(secret: str, body: bytes, ts: int) -> str:
    mac = hmac.new(secret.encode('utf-8'), msg=str(ts).encode('utf-8') + b'.' + body, digestmod=hashlib.sha256)
    return mac.hexdigest()


def test_webhook_guard_hmac_and_replay(monkeypatch):
    monkeypatch.setenv('GENERIC_WEBHOOK_SECRET', 's3cr3t')
    client = TestClient(app)
    body = json.dumps({'hello': 'world'}).encode()
    ts = int(time.time())
    sig = make_sig('s3cr3t', body, ts)

    # First request should pass
    r1 = client.post('/api/v1/webhooks/generic', content=body, headers={'X-Timestamp': str(ts), 'X-Signature': sig, 'Content-Type': 'application/json'})
    assert r1.status_code in (200, 201, 202)

    # Replay with same ts/signature should be blocked
    r2 = client.post('/api/v1/webhooks/generic', content=body, headers={'X-Timestamp': str(ts), 'X-Signature': sig, 'Content-Type': 'application/json'})
    assert r2.status_code == 409

    # Stale timestamp should be rejected
    stale_ts = ts - 999999
    stale_sig = make_sig('s3cr3t', body, stale_ts)
    r3 = client.post('/api/v1/webhooks/generic', content=body, headers={'X-Timestamp': str(stale_ts), 'X-Signature': stale_sig, 'Content-Type': 'application/json'})
    assert r3.status_code == 401


def test_webhook_bad_signature_and_large(monkeypatch):
    monkeypatch.setenv('GENERIC_WEBHOOK_SECRET', 's3cr3t')
    client = TestClient(app)
    body = json.dumps({'hello': 'world'}).encode()
    ts = int(time.time())
    # bad sig
    bad_sig = '0' * 64
    r1 = client.post('/api/v1/webhooks/generic', content=body, headers={'X-Timestamp': str(ts), 'X-Signature': bad_sig, 'Content-Type': 'application/json'})
    assert r1.status_code == 401

    # oversized body
    monkeypatch.setenv('WEBHOOK_MAX_BYTES', '10')
    big = b'a' * 1024
    sig = make_sig('s3cr3t', big, ts)
    r2 = client.post('/api/v1/webhooks/generic', content=big, headers={'X-Timestamp': str(ts), 'X-Signature': sig, 'Content-Type': 'application/json'})
    assert r2.status_code == 413


def test_webhook_db_backed_replay(monkeypatch, tmp_path):
    # Configure middleware to use a temporary sqlite DB and ensure replay detection works
    dbp = tmp_path / 'replay.db'
    monkeypatch.setenv('WEBHOOK_REPLAY_DB_PATH', str(dbp))
    monkeypatch.setenv('GENERIC_WEBHOOK_SECRET', 's3cr3t')
    client = TestClient(app)
    body = json.dumps({'x': 'y'}).encode()
    ts = int(time.time())
    sig = make_sig('s3cr3t', body, ts)
    # first should pass
    r1 = client.post('/api/v1/webhooks/generic', content=body, headers={'X-Timestamp': str(ts), 'X-Signature': sig, 'Content-Type': 'application/json'})
    assert r1.status_code in (200,201,202)
    # second should be detected as replay
    r2 = client.post('/api/v1/webhooks/generic', content=body, headers={'X-Timestamp': str(ts), 'X-Signature': sig, 'Content-Type': 'application/json'})
    assert r2.status_code == 409


def test_webhook_audit_entries(monkeypatch, tmp_path):
    # Ensure audit writes occur for events: missing headers, bad sig
    audit_path = tmp_path / 'audit.log'
    # Point audit logger to tmp
    import src.audit.logger as al
    al.AUDIT_PATH = audit_path

    monkeypatch.setenv('GENERIC_WEBHOOK_SECRET', 's3cr3t')
    client = TestClient(app)

    # missing headers -> writes audit entry
    r1 = client.post('/api/v1/webhooks/generic', content=b'{}', headers={'Content-Type': 'application/json'})
    assert r1.status_code == 400

    # bad signature -> writes audit entry
    ts = int(time.time())
    bad_sig = '0'*64
    r2 = client.post('/api/v1/webhooks/generic', content=b'{}', headers={'X-Timestamp': str(ts), 'X-Signature': bad_sig, 'Content-Type': 'application/json'})
    assert r2.status_code in (401, 409)

    # Read audit file and check entries
    with open(audit_path, 'r', encoding='utf-8') as fh:
        lines = [l.strip() for l in fh if l.strip()]
    assert len(lines) >= 2
    parsed = [json.loads(l) for l in lines]
    ev_names = {p.get('event') for p in parsed}
    assert 'webhook_missing_headers' in ev_names
    # Depending on middleware DB state the second request may be a bad_signature or detected as a replay
    assert ('webhook_bad_signature' in ev_names) or ('webhook_replay_detected' in ev_names)

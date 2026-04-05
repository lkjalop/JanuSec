import os
import sqlite3
import hmac
import hashlib
import base64
import importlib

from scripts import verify_approval_audit as v


def _init_db(path):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE approval_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT,
        event_type TEXT,
        payload TEXT,
        ts TEXT,
        prev_hash TEXT,
        hmac TEXT
    )
    ''')
    conn.commit()
    conn.close()


def _append_event(conn, token, event_type, payload, ts, prev_hash, secret):
    mac_input = (str(prev_hash) + token + event_type + (payload or '') + str(ts)).encode('utf-8')
    h = hmac.new(secret.encode('utf-8'), mac_input, hashlib.sha256).hexdigest() if secret else ''
    cur = conn.cursor()
    cur.execute('INSERT INTO approval_events (token,event_type,payload,ts,prev_hash,hmac) VALUES (?,?,?,?,?,?)',
                (token, event_type, payload, ts, prev_hash, h))
    conn.commit()
    return h


def test_verify_token_ok(tmp_path, monkeypatch):
    db = tmp_path / 'audit.db'
    _init_db(str(db))
    secret = 's3cr3t-key'
    conn = sqlite3.connect(str(db))
    prev = ''
    prev = _append_event(conn, 't1', 'request', '{"a":1}', '2026-01-08T00:00:00', prev, secret)
    prev = _append_event(conn, 't1', 'approve', '{"by":"u1"}', '2026-01-08T00:01:00', prev, secret)
    conn.close()
    monkeypatch.setenv('APPROVAL_DB_PATH', str(db))
    monkeypatch.setenv('APPROVAL_AUDIT_HMAC_KEY', secret)
    importlib.reload(v)
    report = v.verify_token('t1')
    assert report['ok'] is True
    assert len(report['events']) == 2


def test_verify_token_bad(tmp_path, monkeypatch):
    db = tmp_path / 'audit2.db'
    _init_db(str(db))
    secret = 's3cr3t-key'
    conn = sqlite3.connect(str(db))
    prev = ''
    prev = _append_event(conn, 't2', 'request', '{"a":1}', '2026-01-08T00:00:00', prev, secret)
    # Tamper: compute hmac with different payload
    mac_input = (str(prev) + 't2' + 'approve' + '{"by":"u1-tampered"}' + '2026-01-08T00:01:00').encode('utf-8')
    bad_h = hmac.new('badkey'.encode('utf-8'), mac_input, hashlib.sha256).hexdigest()
    cur = conn.cursor()
    cur.execute('INSERT INTO approval_events (token,event_type,payload,ts,prev_hash,hmac) VALUES (?,?,?,?,?,?)',
                ('t2', 'approve', '{"by":"u1"}', '2026-01-08T00:01:00', prev, bad_h))
    conn.commit()
    conn.close()
    monkeypatch.setenv('APPROVAL_DB_PATH', str(db))
    monkeypatch.setenv('APPROVAL_AUDIT_HMAC_KEY', secret)
    importlib.reload(v)
    report = v.verify_token('t2')
    assert report['ok'] is False


def test_verify_all(tmp_path, monkeypatch):
    db = tmp_path / 'audit3.db'
    _init_db(str(db))
    secret = 'another-secret'
    conn = sqlite3.connect(str(db))
    prev = ''
    prev = _append_event(conn, 'a', 'r', '{}', '2026-01-08T00:00:00', prev, secret)
    prev = _append_event(conn, 'a', 'ap', '{}', '2026-01-08T00:01:00', prev, secret)
    prev = ''
    prev = _append_event(conn, 'b', 'r', '{}', '2026-01-08T00:00:00', prev, secret)
    conn.close()
    monkeypatch.setenv('APPROVAL_DB_PATH', str(db))
    monkeypatch.setenv('APPROVAL_AUDIT_HMAC_KEY', secret)
    importlib.reload(v)
    reports = v.verify_all()
    assert isinstance(reports, list)
    assert any(r['token'] == 'a' and r['ok'] for r in reports)
    assert any(r['token'] == 'b' and r['ok'] for r in reports)


def test_load_secret_kms(monkeypatch):
    # Provide a base64 ciphertext and mock boto3 kms decrypt
    ct = base64.b64encode(b'somecipher').decode('utf-8')
    monkeypatch.setenv('APPROVAL_AUDIT_HMAC_KMS_CIPHERTEXT', ct)

    class DummyKMS:
        def decrypt(self, CiphertextBlob):
            return {'Plaintext': b'my-kms-secret'}

    def fake_boto3_client(name):
        assert name == 'kms'
        return DummyKMS()

    # Inject a fake boto3 module into sys.modules so `import boto3` inside _load_secret picks it up
    import sys
    import types
    fake_boto3 = types.ModuleType('boto3')
    def fake_client(name):
        assert name == 'kms'
        return DummyKMS()
    fake_boto3.client = fake_client
    sys.modules['boto3'] = fake_boto3
    importlib.reload(v)
    s = v._load_secret()
    assert s == 'my-kms-secret'


def test_load_secret_azure(monkeypatch):
    # Mock Azure SecretClient and DefaultAzureCredential
    monkeypatch.setenv('APPROVAL_AUDIT_HMAC_AZURE_SECRET_NAME', 'the-secret')
    monkeypatch.setenv('AZURE_KEYVAULT_URL', 'https://example.vault')

    class DummySecret:
        def __init__(self, value):
            self.value = value

    class DummyClient:
        def __init__(self, vault_url, credential):
            pass
        def get_secret(self, name):
            assert name == 'the-secret'
            return DummySecret('azure-secret-value')

    # Inject fake azure modules so imports inside _load_secret resolve
    import sys
    import types
    azure_identity = types.ModuleType('azure.identity')
    azure_kv_secrets = types.ModuleType('azure.keyvault.secrets')
    azure_identity.DefaultAzureCredential = lambda: None
    azure_kv_secrets.SecretClient = DummyClient
    sys.modules['azure.identity'] = azure_identity
    sys.modules['azure.keyvault.secrets'] = azure_kv_secrets
    importlib.reload(v)
    s = v._load_secret()
    assert s == 'azure-secret-value'


def test_export_and_sign(tmp_path, monkeypatch):
    db = tmp_path / 'audit4.db'
    _init_db(str(db))
    secret = 'sign-key'
    conn = sqlite3.connect(str(db))
    prev = ''
    prev = _append_event(conn, 'tx', 'r', '{}', '2026-01-08T00:00:00', prev, secret)
    prev = _append_event(conn, 'tx', 'ap', '{}', '2026-01-08T00:01:00', prev, secret)
    conn.close()
    monkeypatch.setenv('APPROVAL_DB_PATH', str(db))
    monkeypatch.setenv('APPROVAL_AUDIT_HMAC_KEY', secret)
    importlib.reload(v)
    report = v.verify_token('tx')
    exported = v.export_report_json(report, sign=True)
    assert '_signature' in exported
    # verify signature correctness
    sig = exported['_signature']
    payload = dict(exported)
    del payload['_signature']
    calc = hmac.new(secret.encode('utf-8'), json.dumps(payload, sort_keys=True).encode('utf-8'), hashlib.sha256).hexdigest()
    assert calc == sig
import os
import tempfile
import sqlite3
import hmac
import hashlib
import base64
import json
import importlib


from scripts import verify_approval_audit as v


def _init_db(path):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE approval_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT,
        event_type TEXT,
        payload TEXT,
        ts TEXT,
        prev_hash TEXT,
        hmac TEXT
    )
    ''')
    conn.commit()
    conn.close()


def _append_event(conn, token, event_type, payload, ts, prev_hash, secret):
    mac_input = (str(prev_hash) + token + event_type + (payload or '') + str(ts)).encode('utf-8')
    h = hmac.new(secret.encode('utf-8'), mac_input, hashlib.sha256).hexdigest() if secret else ''
    cur = conn.cursor()
    cur.execute('INSERT INTO approval_events (token,event_type,payload,ts,prev_hash,hmac) VALUES (?,?,?,?,?,?)',
                (token, event_type, payload, ts, prev_hash, h))
    conn.commit()
    return h


def test_verify_token_ok(tmp_path, monkeypatch):
    db = tmp_path / 'audit.db'
    _init_db(str(db))
    secret = 's3cr3t-key'
    conn = sqlite3.connect(str(db))
    prev = ''
    prev = _append_event(conn, 't1', 'request', '{"a":1}', '2026-01-08T00:00:00', prev, secret)
    prev = _append_event(conn, 't1', 'approve', '{"by":"u1"}', '2026-01-08T00:01:00', prev, secret)
    conn.close()
    monkeypatch.setenv('APPROVAL_DB_PATH', str(db))
    monkeypatch.setenv('APPROVAL_AUDIT_HMAC_KEY', secret)
    importlib.reload(v)
    report = v.verify_token('t1')
    assert report['ok'] is True
    assert len(report['events']) == 2


def test_verify_token_bad(tmp_path, monkeypatch):
    db = tmp_path / 'audit2.db'
    _init_db(str(db))
    secret = 's3cr3t-key'
    conn = sqlite3.connect(str(db))
    prev = ''
    prev = _append_event(conn, 't2', 'request', '{"a":1}', '2026-01-08T00:00:00', prev, secret)
    # Tamper: compute hmac with different payload
    mac_input = (str(prev) + 't2' + 'approve' + '{"by":"u1-tampered"}' + '2026-01-08T00:01:00').encode('utf-8')
    bad_h = hmac.new('badkey'.encode('utf-8'), mac_input, hashlib.sha256).hexdigest()
    cur = conn.cursor()
    cur.execute('INSERT INTO approval_events (token,event_type,payload,ts,prev_hash,hmac) VALUES (?,?,?,?,?,?)',
                ('t2', 'approve', '{"by":"u1"}', '2026-01-08T00:01:00', prev, bad_h))
    conn.commit()
    conn.close()
    monkeypatch.setenv('APPROVAL_DB_PATH', str(db))
    monkeypatch.setenv('APPROVAL_AUDIT_HMAC_KEY', secret)
    importlib.reload(v)
    report = v.verify_token('t2')
    assert report['ok'] is False


def test_verify_all(tmp_path, monkeypatch):
    db = tmp_path / 'audit3.db'
    _init_db(str(db))
    secret = 'another-secret'
    conn = sqlite3.connect(str(db))
    prev = ''
    prev = _append_event(conn, 'a', 'r', '{}', '2026-01-08T00:00:00', prev, secret)
    prev = _append_event(conn, 'a', 'ap', '{}', '2026-01-08T00:01:00', prev, secret)
    prev = ''
    prev = _append_event(conn, 'b', 'r', '{}', '2026-01-08T00:00:00', prev, secret)
    conn.close()
    monkeypatch.setenv('APPROVAL_DB_PATH', str(db))
    monkeypatch.setenv('APPROVAL_AUDIT_HMAC_KEY', secret)
    importlib.reload(v)
    reports = v.verify_all()
    assert isinstance(reports, list)
    assert any(r['token'] == 'a' and r['ok'] for r in reports)
    assert any(r['token'] == 'b' and r['ok'] for r in reports)

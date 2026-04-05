import os
import sqlite3
import json
import tempfile
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
    conn.commit(); conn.close()


def _append_event(conn, token, event_type, payload, ts, prev_hash, secret):
    import hmac, hashlib
    mac_input = (str(prev_hash) + token + event_type + (payload or '') + str(ts)).encode('utf-8')
    h = hmac.new(secret.encode('utf-8'), mac_input, hashlib.sha256).hexdigest() if secret else ''
    cur = conn.cursor()
    cur.execute('INSERT INTO approval_events (token,event_type,payload,ts,prev_hash,hmac) VALUES (?,?,?,?,?,?)',
                (token, event_type, payload, ts, prev_hash, h))
    conn.commit()
    return h


def test_cli_export_and_verify(tmp_path, monkeypatch):
    db = tmp_path / 'cli.db'
    _init_db(str(db))
    secret = 'cli-secret'
    conn = sqlite3.connect(str(db))
    prev = ''
    prev = _append_event(conn, 'cli1', 'r', '{}', '2026-01-08T00:00:00', prev, secret)
    prev = _append_event(conn, 'cli1', 'ap', '{}', '2026-01-08T00:01:00', prev, secret)
    conn.close()
    monkeypatch.setenv('APPROVAL_DB_PATH', str(db))
    monkeypatch.setenv('APPROVAL_AUDIT_HMAC_KEY', secret)
    report = v.verify_token('cli1')
    out = v.export_report_json(report, sign=True, key_id=None)
    tmp = tmp_path / 'cli_export.json'
    tmp.write_text(json.dumps(out), encoding='utf-8')
    # verify via helper
    assert v.verify_exported_report(json.loads(tmp.read_text(encoding='utf-8')))

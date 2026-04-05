from __future__ import annotations
import os
import sqlite3
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

DEFAULT_DB_PATH = 'data/approvals.db'


def _db_path():
    return os.environ.get('APPROVAL_DB_PATH', DEFAULT_DB_PATH)


def _ensure_db_dir():
    path = _db_path()
    dirn = os.path.dirname(path) or '.'
    os.makedirs(dirn, exist_ok=True)


def _get_conn():
    path = _db_path()
    _ensure_db_dir()
    conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS approvals (
        token TEXT PRIMARY KEY,
        request_json TEXT,
        requested_at TEXT,
        expires_at TEXT,
        status TEXT,
        approved_at TEXT,
        approver TEXT,
        revoked_at TEXT,
        revoked_by TEXT,
        notes TEXT
    )
    ''')
    # event timeline table for multi-approve and audit
    cur.execute('''
    CREATE TABLE IF NOT EXISTS approval_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL,
        event_type TEXT NOT NULL,
        payload TEXT,
        ts REAL NOT NULL,
        prev_hash TEXT,
        hmac TEXT
    )
    ''')
    # Ensure schema is correct: if table exists but missing expected columns, recreate it
    cur.execute("PRAGMA table_info('approval_events')")
    cols = [r[1] for r in cur.fetchall()]
    if 'prev_hash' not in cols or 'hmac' not in cols:
        cur.execute('DROP TABLE IF EXISTS approval_events')
        cur.execute('''
        CREATE TABLE approval_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload TEXT,
            ts REAL NOT NULL,
            prev_hash TEXT,
            hmac TEXT
        )
        ''')
    cur.execute('CREATE INDEX IF NOT EXISTS idx_approval_token ON approval_events(token)')
    # policies table for N-of-M and other approval rules
    cur.execute('''
    CREATE TABLE IF NOT EXISTS approval_policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        action_pattern TEXT,
        n_required INTEGER,
        m_total INTEGER,
        approver_pool_json TEXT,
        scope_json TEXT,
        enabled INTEGER DEFAULT 1,
        created_at TEXT,
        updated_at TEXT
    )
    ''')
    conn.commit(); conn.close()


def save_request(token: str, request_obj: Dict[str, Any], expires_at: Optional[str] = None):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO approvals(token,request_json,requested_at,expires_at,status) VALUES (?,?,?,?,?)', (
        token, json.dumps(request_obj), datetime.utcnow().isoformat() + 'Z', expires_at, 'requested'
    ))
    conn.commit(); conn.close()
    # append event timeline
    try:
        append_event(token, 'request', {'request': request_obj, 'expires_at': expires_at})
    except Exception:
        pass


def save_approve(token: str, approver: str, note: Optional[str] = None):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('UPDATE approvals SET status=?, approved_at=?, approver=?, notes=? WHERE token=?', (
        'approved', datetime.utcnow().isoformat() + 'Z', approver, note, token
    ))
    conn.commit(); conn.close()
    try:
        append_event(token, 'approve', {'approver': approver, 'note': note})
    except Exception:
        pass


def save_revoke(token: str, revoked_by: str, reason: Optional[str] = None):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('UPDATE approvals SET status=?, revoked_at=?, revoked_by=?, notes=? WHERE token=?', (
        'revoked', datetime.utcnow().isoformat() + 'Z', revoked_by, reason, token
    ))
    conn.commit(); conn.close()
    try:
        append_event(token, 'revoke', {'revoked_by': revoked_by, 'reason': reason})
    except Exception:
        pass


def get_status(token: str) -> Optional[Dict[str, Any]]:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM approvals WHERE token=?', (token,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    out = dict(row)
    # parse JSON field
    if out.get('request_json'):
        try:
            out['request'] = json.loads(out['request_json'])
        except Exception:
            out['request'] = None
    # attach recent events
    try:
        out['events'] = get_events(token)
    except Exception:
        out['events'] = []
    return out


def list_all() -> List[Dict[str, Any]]:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM approvals ORDER BY requested_at DESC')
    rows = cur.fetchall(); conn.close()
    out = []
    for r in rows:
        d = dict(r)
        if d.get('request_json'):
            try:
                d['request'] = json.loads(d['request_json'])
            except Exception:
                d['request'] = None
        out.append(d)
    return out


def append_event(token: str, event_type: str, payload: Dict[str, Any]):
    # ensure db/tables exist
    init_db()
    conn = _get_conn()
    cur = conn.cursor()
    import hmac as _hmac
    import hashlib as _hashlib
    # compute prev_hash
    cur.execute('SELECT hmac FROM approval_events WHERE token=? ORDER BY id DESC LIMIT 1', (token,))
    last = cur.fetchone()
    prev = ''
    if last:
        try:
            prev = last['hmac'] if last['hmac'] else ''
        except Exception:
            prev = ''
    payload_text = json.dumps(payload, sort_keys=True)
    ts = datetime.utcnow().timestamp()
    secret = os.environ.get('APPROVAL_AUDIT_HMAC_KEY', '')
    # compute HMAC over prev || token || event_type || payload || ts
    mac_input = (str(prev) + token + event_type + payload_text + str(ts)).encode('utf-8')
    if secret:
        digest = _hmac.new(secret.encode('utf-8'), mac_input, _hashlib.sha256).hexdigest()
    else:
        # no secret: produce an unsigned marker
        digest = ''
    cur.execute('INSERT INTO approval_events(token, event_type, payload, ts, prev_hash, hmac) VALUES (?,?,?,?,?,?)',
                (token, event_type, payload_text, ts, prev, digest))
    conn.commit()
    conn.close()


def get_events(token: str) -> List[Dict[str, Any]]:
    path = _db_path()
    if not os.path.exists(path):
        return []
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('SELECT event_type, payload, ts FROM approval_events WHERE token=? ORDER BY id ASC', (token,))
    rows = cur.fetchall()
    conn.close()
    out = []
    for ev, payload, ts in rows:
        try:
            p = json.loads(payload) if payload else None
        except Exception:
            p = payload
        out.append({'event': ev, 'payload': p, 'ts': float(ts)})
    return out


def count_approvals(token: str) -> int:
    path = _db_path()
    if not os.path.exists(path):
        return 0
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(1) FROM approval_events WHERE token=? AND event_type='approve'", (token,))
    row = cur.fetchone()
    conn.close()
    return int(row[0]) if row else 0


def get_approvers_for_token(token: str) -> list:
    path = _db_path()
    if not os.path.exists(path):
        return []
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT payload FROM approval_events WHERE token=? AND event_type='approve' ORDER BY id ASC", (token,))
    rows = cur.fetchall(); conn.close()
    approvers = []
    for (payload,) in rows:
        try:
            p = json.loads(payload) if payload else {}
        except Exception:
            p = {}
        a = p.get('approver') or p.get('approver_id')
        if a and a not in approvers:
            approvers.append(a)
    return approvers


def query_approvals(status: Optional[str] = None, approver: Optional[str] = None, since: Optional[str] = None, until: Optional[str] = None, offset: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
    conn = _get_conn()
    cur = conn.cursor()
    clauses = []
    params = []
    if status:
        clauses.append('status=?')
        params.append(status)
    if approver:
        clauses.append('approver=?')
        params.append(approver)
    if since:
        clauses.append('requested_at>=?')
        params.append(since)
    if until:
        clauses.append('requested_at<=?')
        params.append(until)
    where = ('WHERE ' + ' AND '.join(clauses)) if clauses else ''
    sql = f'SELECT * FROM approvals {where} ORDER BY requested_at DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        if d.get('request_json'):
            try:
                d['request'] = json.loads(d['request_json'])
            except Exception:
                d['request'] = None
        out.append(d)
    return out


def save_policy(name: str, action_pattern: str, n_required: int, m_total: int, approver_pool: Optional[list] = None, scope: Optional[Dict[str, Any]] = None, enabled: bool = True):
    now = datetime.utcnow().isoformat() + 'Z'
    conn = _get_conn()
    cur = conn.cursor()
    # preserve existing created_at when updating
    cur.execute('SELECT created_at FROM approval_policies WHERE name=?', (name,))
    row = cur.fetchone()
    created_at = row['created_at'] if row and row.get('created_at') else now
    cur.execute('INSERT OR REPLACE INTO approval_policies(name, action_pattern, n_required, m_total, approver_pool_json, scope_json, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)', (
        name, action_pattern, n_required, m_total, json.dumps(approver_pool) if approver_pool else None, json.dumps(scope) if scope else None, 1 if enabled else 0, created_at, now
    ))
    conn.commit(); conn.close()


def get_policy_by_name(name: str) -> Optional[Dict[str, Any]]:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM approval_policies WHERE name=?', (name,))
    row = cur.fetchone(); conn.close()
    if not row:
        return None
    d = dict(row)
    if d.get('scope_json'):
        try:
            d['scope'] = json.loads(d['scope_json'])
        except Exception:
            d['scope'] = None
    return d


def list_policies() -> List[Dict[str, Any]]:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM approval_policies ORDER BY id ASC')
    rows = cur.fetchall(); conn.close()
    out = []
    for r in rows:
        d = dict(r)
        if d.get('scope_json'):
            try:
                d['scope'] = json.loads(d['scope_json'])
            except Exception:
                d['scope'] = None
        if d.get('approver_pool_json'):
            try:
                d['approver_pool'] = json.loads(d['approver_pool_json'])
            except Exception:
                d['approver_pool'] = None
        out.append(d)
    return out


def delete_policy(name: str):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('DELETE FROM approval_policies WHERE name=?', (name,))
    conn.commit(); conn.close()


def find_policy_for_action(action: str) -> Optional[Dict[str, Any]]:
    # naive matching: prefer exact match then prefix/substring; action_pattern is a simple pattern
    import re
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM approval_policies WHERE enabled=1 ORDER BY id ASC')
    rows = cur.fetchall(); conn.close()
    # collect candidates
    exact = None
    regex_full = None
    prefix = None
    substring = None
    for r in rows:
        d = dict(r)
        pat = d.get('action_pattern') or ''
        try:
            if pat == action:
                exact = d; break
            # treat patterns starting and ending with / as regex: /pattern/
            if len(pat) >= 2 and pat.startswith('/') and pat.rfind('/') > 0:
                try:
                    body = pat.strip('/')
                    rx = re.compile(body)
                    if rx.fullmatch(action):
                        regex_full = d
                        break
                except Exception:
                    pass
            if action.startswith(pat):
                if prefix is None:
                    prefix = d
                continue
            if pat in action:
                if substring is None:
                    substring = d
        except Exception:
            continue
    chosen = exact or regex_full or prefix or substring
    if chosen and chosen.get('scope_json'):
        try:
            chosen['scope'] = json.loads(chosen['scope_json'])
        except Exception:
            chosen['scope'] = None
    if chosen and chosen.get('approver_pool_json'):
        try:
            chosen['approver_pool'] = json.loads(chosen['approver_pool_json'])
        except Exception:
            chosen['approver_pool'] = None
    return chosen


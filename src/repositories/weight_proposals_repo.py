import os
import sqlite3
import json
import time
from typing import Optional, Dict, Any, List

DB = os.environ.get('WEIGHT_PROPOSALS_DB', 'data/weight_proposals.db')


def _conn():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    conn = _conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS weight_proposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT,
            proposer TEXT,
            candidate_json TEXT,
            created_at INTEGER,
            applied_at INTEGER,
            replay_report_json TEXT,
            ab_test_id TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def persist_proposal(rule_id: str, proposer: Optional[str], candidate: Dict[str, Any], ab_test_id: Optional[str] = None) -> int:
    init_db()
    conn = _conn()
    cur = conn.cursor()
    now = int(time.time())
    cur.execute('INSERT INTO weight_proposals(rule_id,proposer,candidate_json,created_at,ab_test_id) VALUES (?,?,?,?,?)',
                (rule_id, proposer, json.dumps(candidate), now, ab_test_id))
    cid = cur.lastrowid
    conn.commit(); conn.close()
    return cid


def write_replay_report(proposal_id: int, report: Dict[str, Any]) -> None:
    init_db()
    conn = _conn(); cur = conn.cursor()
    cur.execute('UPDATE weight_proposals SET replay_report_json=? WHERE id=?', (json.dumps(report), proposal_id))
    conn.commit(); conn.close()


def mark_applied(proposal_id: int) -> None:
    conn = _conn(); cur = conn.cursor()
    cur.execute('UPDATE weight_proposals SET applied_at=? WHERE id=?', (int(time.time()), proposal_id))
    conn.commit(); conn.close()


def list_recent(limit: int = 50) -> List[Dict[str, Any]]:
    init_db()
    conn = _conn(); cur = conn.cursor()
    cur.execute('SELECT id,rule_id,proposer,created_at,applied_at,ab_test_id FROM weight_proposals ORDER BY id DESC LIMIT ?', (limit,))
    rows = cur.fetchall(); conn.close()
    out = []
    for r in rows:
        out.append({k: r[k] for k in r.keys()})
    return out


def get_proposal(proposal_id: int) -> Optional[Dict[str, Any]]:
    init_db()
    conn = _conn(); cur = conn.cursor()
    cur.execute('SELECT * FROM weight_proposals WHERE id=?', (proposal_id,))
    row = cur.fetchone(); conn.close()
    if not row:
        return None
    d = {k: row[k] for k in row.keys()}
    if d.get('candidate_json'):
        try:
            d['candidate'] = json.loads(d['candidate_json'])
        except Exception:
            d['candidate'] = d['candidate_json']
    if d.get('replay_report_json'):
        try:
            d['replay_report'] = json.loads(d['replay_report_json'])
        except Exception:
            d['replay_report'] = d['replay_report_json']
    return d

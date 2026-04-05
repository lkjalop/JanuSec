"""Simple repository adapter for calibration proposals.

This adapter prefers a configured DB via `db.database` if available; otherwise
falls back to a local SQLite file `calibration_proposals.sqlite` placed under
the project root. It provides `persist_proposal` and `list_proposals` helpers.
"""
from __future__ import annotations

import os
import json
import sqlite3
import threading
import time
from typing import Optional, List, Dict, Any

_LOCK = threading.Lock()
_DB_PATH = os.getenv('CALIBRATION_PROPOSALS_DB', 'calibration_proposals.sqlite')


def _ensure_table(conn: sqlite3.Connection):
    conn.execute('''
    CREATE TABLE IF NOT EXISTS calibration_proposals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL,
        k REAL,
        x0 REAL,
        loglik REAL,
        samples INTEGER,
        tp_counts TEXT,
        fp_counts TEXT,
        ks REAL,
        accepted INTEGER DEFAULT 0,
        rejected INTEGER DEFAULT 0,
        created_at REAL
    )
    ''')
    conn.commit()


def _conn():
    path = _DB_PATH
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    return sqlite3.connect(path, check_same_thread=False)


def persist_proposal(proposal: Dict[str, Any]) -> None:
    with _LOCK:
        conn = _conn()
        try:
            _ensure_table(conn)
            conn.execute(
                'INSERT INTO calibration_proposals (ts,k,x0,loglik,samples,tp_counts,fp_counts,ks,accepted,rejected,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                (
                    float(proposal.get('ts', time.time())),
                    float(proposal.get('k', 0.0)),
                    float(proposal.get('x0', 0.0)),
                    float(proposal.get('loglik', 0.0)),
                    int(proposal.get('samples', 0)),
                    json.dumps(proposal.get('tp_factor_counts', {})),
                    json.dumps(proposal.get('fp_factor_counts', {})),
                    float(proposal.get('ks_tp_fp') or 0.0),
                    1 if proposal.get('accepted') else 0,
                    1 if proposal.get('rejected') else 0,
                    float(proposal.get('ts', time.time())),
                )
            )
            conn.commit()
        finally:
            conn.close()


def list_proposals(limit: int = 100) -> List[Dict[str, Any]]:
    with _LOCK:
        conn = _conn()
        try:
            _ensure_table(conn)
            cur = conn.execute('SELECT ts,k,x0,loglik,samples,tp_counts,fp_counts,ks,accepted,rejected,created_at FROM calibration_proposals ORDER BY created_at DESC LIMIT ?', (limit,))
            out = []
            for r in cur.fetchall():
                out.append({
                    'ts': r[0], 'k': r[1], 'x0': r[2], 'loglik': r[3], 'samples': r[4],
                    'tp_factor_counts': json.loads(r[5] or '{}'), 'fp_factor_counts': json.loads(r[6] or '{}'), 'ks_tp_fp': r[7],
                    'accepted': bool(r[8]), 'rejected': bool(r[9]), 'created_at': r[10]
                })
            return out
        finally:
            conn.close()


__all__ = ['persist_proposal','list_proposals']

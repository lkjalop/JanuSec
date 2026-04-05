import os
import sqlite3
import json
import time
from typing import List, Dict, Any


DB_PATH = os.environ.get('LLM_CLAIMS_DB', 'data/llm_claims.db')


def _get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS claims(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            decision_id TEXT,
            claim_text TEXT,
            claim_type TEXT,
            evidence_refs TEXT,
            confidence REAL,
            created_at REAL,
            adjudicated INTEGER DEFAULT 0,
            is_correct INTEGER DEFAULT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def record_claim(decision_id: str, claim_text: str, claim_type: str, evidence_refs: List[Dict[str, Any]] | None = None, confidence: float | None = None) -> int:
    init_db()
    conn = _get_conn()
    cur = conn.cursor()
    refs = json.dumps(evidence_refs or [])
    ts = time.time()
    cur.execute(
        "INSERT INTO claims(decision_id, claim_text, claim_type, evidence_refs, confidence, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (decision_id, claim_text, claim_type, refs, float(confidence) if confidence is not None else None, ts),
    )
    cid = cur.lastrowid
    conn.commit()
    conn.close()
    return cid


def mark_adjudication(claim_id: int, is_correct: bool) -> None:
    init_db()
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE claims SET adjudicated=1, is_correct=? WHERE id=?", (1 if is_correct else 0, claim_id))
    conn.commit()
    conn.close()


def list_unadjudicated(limit: int = 100) -> List[Dict[str, Any]]:
    init_db()
    conn = _get_conn()
    cur = conn.cursor()
    rows = cur.execute("SELECT * FROM claims WHERE adjudicated=0 ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def stats() -> Dict[str, Any]:
    init_db()
    conn = _get_conn()
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(1) as c FROM claims").fetchone()[0]
    adjud = cur.execute("SELECT COUNT(1) as c FROM claims WHERE adjudicated=1").fetchone()[0]
    correct = cur.execute("SELECT COUNT(1) as c FROM claims WHERE adjudicated=1 AND is_correct=1").fetchone()[0]
    conn.close()
    precision = (correct / adjud) if adjud else None
    return {'total': int(total), 'adjudicated': int(adjud), 'correct': int(correct), 'precision': precision}

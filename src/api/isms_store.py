from __future__ import annotations

import os
import sqlite3
import json
from typing import List, Dict, Any, Optional

DB_PATH = os.getenv('ISMS_DB_PATH') or os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'isms_index.db'))
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def _get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        filename TEXT,
        manifest TEXT,
        tenant_id TEXT,
        inserted_at REAL
    )
    ''')
    conn.commit()
    conn.close()


def add_entry(id: str, filename: str, manifest: Dict[str, Any], tenant_id: Optional[str] = None):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO evidence (id, filename, manifest, tenant_id, inserted_at) VALUES (?, ?, ?, ?, ?)', (id, filename, json.dumps(manifest), tenant_id or 'default', float(manifest.get('collected_at') or 0)))
    conn.commit()
    conn.close()


def list_entries(limit: int = 100, tenant: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = _get_conn()
    cur = conn.cursor()
    if tenant:
        cur.execute('SELECT * FROM evidence WHERE tenant_id = ? ORDER BY inserted_at DESC LIMIT ?', (tenant, limit))
    else:
        cur.execute('SELECT * FROM evidence ORDER BY inserted_at DESC LIMIT ?', (limit,))
    rows = cur.fetchall()
    conn.close()
    out: List[Dict[str, Any]] = []
    for r in rows:
        out.append({'id': r['id'], 'filename': r['filename'], 'manifest': json.loads(r['manifest']) if r['manifest'] else {}, 'tenant_id': r['tenant_id'], 'inserted_at': r['inserted_at']})
    return out


def scan_evidence_dir(evidence_dir: str):
    # On startup: scan evidence_dir for JSON manifests and populate DB
    # Avoid scanning large evidence directories during test/demo runs
    try:
        if os.getenv('PYTEST_CURRENT_TEST') or os.getenv('TEST_HELPERS_ENABLED', '0').lower() in {'1','true','yes'} or os.getenv('PLATFORM_LITE_INIT', '0').lower() in {'1','true','yes'}:
            init_db()
            return
    except Exception:
        pass
    init_db()
    try:
        for fn in os.listdir(evidence_dir):
            if not fn.endswith('.json'):
                continue
            path = os.path.join(evidence_dir, fn)
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    j = json.load(fh)
            except Exception:
                continue
            manifest = j.get('manifest') or j.get('manifest', {})
            eid = manifest.get('id') or fn.replace('.json', '')
            tenant = manifest.get('tenant_id') or 'default'
            add_entry(eid, fn, manifest, tenant)
    except FileNotFoundError:
        # evidence directory doesn't exist; that's fine during tests
        return

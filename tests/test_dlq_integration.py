import asyncio
import json
import os
import time

import pytest

# Ensure project src on path for imports
import sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SRC = os.path.join(ROOT, 'src')
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from db import adapter as db_adapter
from src.core.dlq_manager import DLQManager


@pytest.mark.asyncio
async def test_dlq_retry_with_upsert_stub(monkeypatch):
    # Ensure sqlite pool active
    try:
        import os as _os
        # Ensure DB isn't disabled in env for the test
        _os.environ.pop('DISABLE_DB', None)
        await __import__('db.database', fromlist=['init_pool']).init_pool()
    except Exception:
        pass

    # Ensure table exists
    await db_adapter.execute('''
        CREATE TABLE IF NOT EXISTS decisions_dlq (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT,
            payload TEXT,
            error TEXT,
            attempts INTEGER DEFAULT 0,
            last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP,
            next_retry REAL NULL
        )
    ''')

    event_id = 'test-integ-' + str(int(time.time()*1000))
    payload = {'event_id': event_id, 'foo': 'bar'}
    # Insert DLQ row
    await db_adapter.execute('INSERT INTO decisions_dlq (event_id, payload, error, attempts, last_attempt) VALUES (?,?,?,?,CURRENT_TIMESTAMP)', event_id, json.dumps(payload), 'simulated', 0)

    rows = await db_adapter.fetch('SELECT id, event_id, payload, attempts FROM decisions_dlq WHERE event_id=$1', event_id)
    assert rows and len(rows) == 1
    dlq_row = rows[0]
    dlq_id = dlq_row['id']

    # Async test double that fails once then succeeds
    calls = {'count': 0}

    async def upsert_double(event_id_arg, d, tenant_id=None):
        calls['count'] += 1
        if calls['count'] == 1:
            raise RuntimeError('transient')
        return None

    # Patch into repositories.decisions_repo
    monkeypatch.setattr('repositories.decisions_repo.upsert_decision', upsert_double, raising=False)

    mgr = DLQManager(poll_interval_s=1, max_attempts=3)
    ok1 = await mgr._attempt_redeliver(dlq_row)
    assert ok1 is False
    rows_after1 = await db_adapter.fetch('SELECT id, attempts FROM decisions_dlq WHERE id=$1', dlq_id)
    assert rows_after1 and int(rows_after1[0]['attempts']) >= 1

    ok2 = await mgr._attempt_redeliver(dlq_row)
    assert ok2 is True
    rows_after2 = await db_adapter.fetch('SELECT id FROM decisions_dlq WHERE id=$1', dlq_id)
    assert not rows_after2
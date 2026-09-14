#!/usr/bin/env python3
"""
Insert a synthetic DLQ row using the project's DB adapter and exercise the DLQ endpoints:
- Insert DLQ row
- GET /api/v1/dlq to confirm
- GET /api/v1/dlq/{id}
- POST /api/v1/dlq/{id}/retry (unauthenticated; requires admin normally, but retry allows empty request in current API if check_admin_token_async(request) is only enforced if request present)
- POST /api/v1/dlq/{id}/requeue (requires admin auth; we will call and expect 401 unless ADMIN_UI_TOKEN provided)
- GET /api/v1/dlq/{id}/audit (requires admin auth; expect 401)

This script mutates local DB (inserts into decisions_dlq). Use with caution.
"""
from __future__ import annotations
import sys
import os
import json
import time
import asyncio
import logging

# Ensure project src is on sys.path so imports like 'db.adapter' resolve
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SRC = os.path.join(ROOT, 'src')
if SRC not in sys.path:
    sys.path.insert(0, SRC)

print('Using project src path:', SRC)


async def main():
    print('Inserting synthetic DLQ row via db.adapter (async)...')
    try:
        from db import adapter as db_adapter
    except Exception as e:
        print('Failed to import db.adapter from project src:', e)
        return
    # Ensure DB pool initialized (init_pool will activate sqlite fallback if asyncpg missing)
    try:
        from db import database as _db
        try:
            await _db.init_pool()
            print('DB pool initialized')
        except Exception as e:
            print('db.init_pool failed (continuing):', e)
    except Exception:
        pass

    payload = {'event_id': 'injected-dlq-' + str(int(time.time() * 1000)), 'payload': {'fake': 'payload'}, 'error': 'simulated error', 'attempts': 0}
    # Use the same SQL shape as the codebase
    sql = "INSERT INTO decisions_dlq (event_id, payload, error, attempts, last_attempt) VALUES ($1, $2, $3, $4, NOW())"
    # Ensure table exists when running against sqlite fallback (migrations may not have run)
    try:
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
        print('Ensured decisions_dlq table exists')
    except Exception as e:
        print('Failed to ensure decisions_dlq table exists (continuing):', e)
    try:
        maybe = db_adapter.execute(sql, payload['event_id'], json.dumps(payload), payload['error'], payload['attempts'])
        if asyncio.iscoroutine(maybe):
            await maybe
        print('Inserted DLQ row for event_id:', payload['event_id'])
    except Exception as exc:
        print('DLQ insert initial attempt failed, will retry with SQLite-compatible SQL:', exc)
        try:
            import datetime
            ts = datetime.datetime.utcnow().isoformat()
            sql2 = 'INSERT INTO decisions_dlq (event_id, payload, error, attempts, last_attempt) VALUES (?,?,?,?,?)'
            maybe2 = db_adapter.execute(sql2, payload['event_id'], json.dumps(payload), payload['error'], payload['attempts'], ts)
            if asyncio.iscoroutine(maybe2):
                await maybe2
            print('Inserted DLQ row (sqlite fallback) for event_id:', payload['event_id'])
        except Exception as exc2:
            print('DLQ insert fallback failed:', exc2)
            return

    # Fetch the latest matching row using db.adapter.fetch
    try:
        rows = await db_adapter.fetch('SELECT id, event_id, payload, error, attempts, last_attempt, next_retry FROM decisions_dlq WHERE event_id=$1 ORDER BY id DESC LIMIT $2', payload['event_id'], 5)
        if not rows:
            print('No rows returned after insert; aborting')
            return
        row = rows[0]
        print('Fetched DLQ row id:', row.get('id'))
    except Exception as exc:
        print('DLQ fetch failed:', exc)
        return

    # Instantiate local DLQManager and attempt redeliver
    try:
        from src.core.dlq_manager import DLQManager
    except Exception:
        # fallback import path
        try:
            from core.dlq_manager import DLQManager
        except Exception as e:
            print('Failed to import DLQManager:', e)
            return

    mgr = DLQManager(poll_interval_s=1, max_attempts=3)
    print('Calling DLQManager._attempt_redeliver for id', row.get('id'))
    try:
        ok = await mgr._attempt_redeliver(row)
        print('Redeliver result:', ok)
    except Exception as e:
        print('Redeliver call failed:', e)

    # Inspect whether DLQ row still exists
    try:
        rows_after = await db_adapter.fetch('SELECT id, event_id, attempts, next_retry FROM decisions_dlq WHERE id=$1', row.get('id'))
        if rows_after:
            print('DLQ row still present after redeliver attempt:', rows_after[0])
        else:
            print('DLQ row deleted after successful redeliver')
    except Exception as exc:
        print('Post-check fetch failed:', exc)


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--stub-upsert', action='store_true', help='Monkeypatch repositories.decisions_repo.upsert_decision to a successful stub')
    args = p.parse_args()
    # Enable debug logging so DLQManager debug traces are visible
    logging.basicConfig(level=logging.DEBUG)
    if args.stub_upsert:
        # Replace upsert_decision with an async stub on the real module so DLQManager will await it
        try:
            import repositories.decisions_repo as dr_mod
            async def _stub_upsert(event_id, d, tenant_id=None):
                logging.debug('Stub upsert called for event_id=%s', event_id)
                return None
            dr_mod.upsert_decision = _stub_upsert
            print('Patched repositories.decisions_repo.upsert_decision with async stub')
        except Exception:
            import types, sys
            mod = types.ModuleType('repositories.decisions_repo')
            async def _stub_upsert(event_id, d, tenant_id=None):
                logging.debug('Stub upsert (new module) called for event_id=%s', event_id)
                return None
            mod.upsert_decision = _stub_upsert
            sys.modules['repositories.decisions_repo'] = mod
            print('Installed stub repositories.decisions_repo.upsert_decision (new module)')
    asyncio.run(main())

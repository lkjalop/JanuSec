import os
import sqlite3
import json
import time
import asyncio
import types

import pytest


@pytest.fixture
def tmp_db(tmp_path):
    dbf = tmp_path / "test_enrich.db"
    conn = sqlite3.connect(str(dbf))
    cur = conn.cursor()
    cur.execute("CREATE TABLE events(event_id TEXT PRIMARY KEY, raw TEXT)")
    cur.execute("CREATE TABLE enrichment_queue(id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, event_id TEXT)")
    conn.commit()
    yield conn
    conn.close()


def run_worker_iteration(db_conn, monkeypatch, enable_hopgraph):
    # Prepare a sample raw event
    event_id = 'evt-1'
    raw = {'context': {'host': 'host1', 'dst_ip': '10.0.0.5', 'domain': 'example.com', 'process': 'procX'}, 'ts': time.time()}
    db_conn.execute('INSERT INTO events(event_id, raw) VALUES(?,?)', (event_id, json.dumps(raw)))
    db_conn.execute('INSERT INTO enrichment_queue(tenant_id, event_id) VALUES(?,?)', ('t1', event_id))
    db_conn.commit()

    # capture calls
    calls = []

    def fake_ingest(payload, source=''):
        calls.append((payload, source))

    monkeypatch.setenv('HOPGRAPH_INGEST_ENABLED', '1' if enable_hopgraph else '0')
    # patch ingest_event into module path used by enrichment worker
    monkeypatch.setattr('src.workers.enrichment_worker.ingest_event', fake_ingest)
    # patch enrich_email used by worker to accept dict input
    def fake_enrich(ev):
        return {'signals': ['s1'], 'meta': {'ok': True}}
    monkeypatch.setattr('src.workers.enrichment_worker.enrich_email', fake_enrich)

    # Run the sqlite processing function directly via asyncio
    from src.workers.enrichment_worker import EnrichmentWorker

    async def _run():
        worker = EnrichmentWorker(db_conn, hopgraph=None)
        # Process a single row using the same sqlite cursor interface
        cur = db_conn.cursor()
        cur.execute("SELECT id, tenant_id, event_id FROM enrichment_queue LIMIT 10")
        rows = cur.fetchall()
        # call private processor
        for r in rows:
            await worker._process_with_sqlite(cur, r)

    asyncio.get_event_loop().run_until_complete(_run())
    return calls


def test_enrichment_worker_hopgraph_disabled(tmp_db, monkeypatch):
    calls = run_worker_iteration(tmp_db, monkeypatch, enable_hopgraph=False)
    assert calls == [], "No hopgraph ingest should be called when disabled"


def test_enrichment_worker_hopgraph_enabled(tmp_db, monkeypatch):
    calls = run_worker_iteration(tmp_db, monkeypatch, enable_hopgraph=True)
    assert len(calls) == 1
    payload, source = calls[0]
    assert source == 'email_enrichment'
    # payload should include expected keys
    for k in ('src_host', 'dst_ip', 'domain', 'process', 'ts'):
        assert k in payload
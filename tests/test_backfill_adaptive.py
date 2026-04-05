import time
import os
import asyncio

from src.api.csv_endpoints import _run_backfill, BACKFILL_JOBS, rehydrate_backfill_jobs
from src.api.deep_analyze_endpoints import _ensure_triage_on_row


def test_adaptive_backfill_basic(tmp_path, monkeypatch):
    # Prepare a fake assessment in REPORT_STORE
    from src.api.deep_analyze_endpoints import REPORT_STORE
    aid = 'test-assess-backfill'
    rows = []
    # create 120 rows with varying triage scores
    for i in range(120):
        tri = float(i % 10) / 9.0  # cycles 0..1
        rows.append({'row_index': i, 'status': 'new', 'factors': ['f'+str(i%3)], 'triage_score': tri})
    REPORT_STORE[aid] = {'assessment_id': aid, 'rows': rows}

    # small window and batch for test
    async def run_job():
        await _run_backfill(aid, target=0.5, window_seconds=0, batch_size=10, tenant_id=None, api_key=None)

    # Run with reduced runtime env
    monkeypatch.setenv('BACKFILL_MAX_RUNTIME_SECONDS', '5')
    monkeypatch.setenv('BACKFILL_BURST_SIZE', '2')
    monkeypatch.setenv('BACKFILL_MIN_TRIAGE', '0.2')

    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_job())

    job = BACKFILL_JOBS.get(aid)
    assert job is not None
    assert job.get('assessment_id') == aid
    # Ensure coverage reached or job completed/cancelled
    assert job.get('status') in ('completed','cancelled')
    # ETA should exist (may be -1 if not calculable)
    assert 'eta_seconds' in job

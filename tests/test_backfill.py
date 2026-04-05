import asyncio
import os

import pytest

from src.api import csv_endpoints as csv_ep
import src.api.deep_analyze_endpoints as deep_mod


@pytest.mark.asyncio
async def test_backfill_selection_and_status(tmp_path, monkeypatch):
    # Prepare fake assessment with 10 rows and varying triage_scores
    aid = 'test-assess-1'
    rows = []
    for i in range(10):
        rows.append({'row_index': i, 'status': 'pending', 'triage_score': float(i) / 9.0})
    fake_assessment = {'assessment_id': aid, 'rows': rows}

    # Mock _get_assessment_cached
    async def fake_run_pipeline(payload):
        # simulate processing by sleeping briefly
        await asyncio.sleep(0.01)
        return {'ok': True}

    def fake_get_assessment_cached(aid_in):
        return fake_assessment

    monkeypatch.setattr(deep_mod, '_get_assessment_cached', fake_get_assessment_cached)
    monkeypatch.setattr(deep_mod, 'run_deep_analyze_pipeline', fake_run_pipeline)

    # Ensure session persist dir exists
    monkeypatch.setenv('SESSION_PERSIST_DIR', str(tmp_path))
    monkeypatch.setenv('BACKFILL_PERSIST_IN_TESTS', '1')

    # Schedule backfill (runs in background)
    res = await csv_ep.csv_deep_analyze_auto_backfill({'assessment_id': aid, 'target_coverage': 0.5, 'window_seconds': 1, 'batch_size': 3})
    assert res['status'] == 'scheduled'

    # Wait for job to start
    await asyncio.sleep(0.2)

    status = await csv_ep.csv_deep_analyze_auto_backfill_status(aid)
    assert status['assessment_id'] == aid
    assert status['status'] in ('running', 'completed')

    # Wait longer for completion
    await asyncio.sleep(2)
    status2 = await csv_ep.csv_deep_analyze_auto_backfill_status(aid)
    assert status2['assessment_id'] == aid
    assert status2['status'] in ('running', 'completed')

    # persisted file exists
    p = os.path.join(os.environ['SESSION_PERSIST_DIR'], 'backfill_jobs', f"{aid}.json")
    assert os.path.exists(p)

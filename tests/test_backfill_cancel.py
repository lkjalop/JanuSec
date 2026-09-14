import time
import json
import os
from fastapi.testclient import TestClient

from src.api.csv_endpoints import BACKFILL_JOBS
from src.api.main import app


def test_backfill_start_and_cancel(tmp_path):
    client = TestClient(app)

    # create a fake assessment file in sessions so backfill can find rows
    aid = 'test-assess-cancel'
    base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(os.getcwd(), 'data', 'sessions')
    out_dir = os.path.join(base, 'assessments')
    os.makedirs(out_dir, exist_ok=True)
    assessment_path = os.path.join(out_dir, f"{aid}.json")
    # minimal assessment with many rows to keep backfill running
    rows = [{'row_index': i, 'raw': {'a': i}, 'status': 'new'} for i in range(50)]
    with open(assessment_path, 'w', encoding='utf-8') as fh:
        fh.write(json.dumps({'assessment_id': aid, 'rows': rows}))

    # start backfill
    resp = client.post('/api/v1/csv/deep_analyze/auto_backfill', json={'assessment_id': aid, 'target_coverage': 0.9, 'batch_size': 5, 'window_seconds': 1})
    assert resp.status_code == 200
    j = resp.json()
    assert j.get('assessment_id') == aid

    # wait briefly for registry to be populated
    time.sleep(0.5)
    job = BACKFILL_JOBS.get(aid)
    assert job is not None
    assert job.get('status') in ('running', 'scheduled', 'completed')

    # request stop
    resp2 = client.post(f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/stop')
    assert resp2.status_code == 200
    time.sleep(0.2)

    # poll until cancelled or timeout
    deadline = time.time() + 5
    final = None
    while time.time() < deadline:
        job = BACKFILL_JOBS.get(aid)
        if job and job.get('status') in ('cancelled', 'stopping'):
            final = job
            break
        time.sleep(0.1)

    assert final is not None, 'Backfill job did not reach cancelled state'
    assert final.get('cancel_requested') is True

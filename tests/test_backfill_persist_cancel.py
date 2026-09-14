import time
import os
import json
from fastapi.testclient import TestClient

from src.api.csv_endpoints import BACKFILL_JOBS, _persist_backfill_job
from src.api.app import app


def test_backfill_persisted_cancel(tmp_path):
    client = TestClient(app)
    aid = 'persist-cancel-test'
    base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(os.getcwd(), 'data', 'sessions')
    jobs_dir = os.path.join(base, 'backfill_jobs')
    os.makedirs(jobs_dir, exist_ok=True)
    # ensure registry clean
    if aid in BACKFILL_JOBS: del BACKFILL_JOBS[aid]

    resp = client.post('/api/v1/csv/deep_analyze/auto_backfill', json={'assessment_id': aid, 'batch_size': 2, 'window_seconds': 1})
    assert resp.status_code == 200
    time.sleep(0.2)
    # request stop
    resp2 = client.post(f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/stop')
    assert resp2.status_code == 200
    time.sleep(0.2)
    # persisted file should exist
    path = os.path.join(jobs_dir, f"{aid}.json")
    assert os.path.exists(path)
    with open(path, 'r', encoding='utf-8') as fh:
        data = json.load(fh)
    assert data.get('cancel_requested') in (True, 1)
    assert data.get('status') in ('cancelled', 'stopping')

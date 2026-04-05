import os
import json
from fastapi.testclient import TestClient

from src.api import csv_endpoints as csv_ep
from src.api import app as appmod

# Use the full FastAPI app so middleware and lifespan are mounted for TestClient
app = appmod.create_app()
client = TestClient(app)

def test_rehydrate_and_cancel(tmp_path, monkeypatch):
    aid = 'rehydrate-test-1'
    base = str(tmp_path)
    monkeypatch.setenv('SESSION_PERSIST_DIR', base)
    jobs_dir = os.path.join(base, 'backfill_jobs')
    os.makedirs(jobs_dir, exist_ok=True)
    # prepare a persisted job file
    job = {'assessment_id': aid, 'status': 'running', 'processed': 2, 'total': 10, 'coverage': 0.2}
    path = os.path.join(jobs_dir, f"{aid}.json")
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(job, fh)
    # rehydrate
    csv_ep.rehydrate_backfill_jobs()
    # ensure job loaded
    assert aid in csv_ep.BACKFILL_JOBS
    # call stop API on the full app (router is mounted at /api/v1/csv)
    resp = client.post(f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/stop')
    assert resp.status_code == 200
    data = resp.json()
    assert data.get('status') in ('stopping', 'stopped')
    # persisted file should still exist
    assert os.path.exists(path)

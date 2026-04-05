import time
from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})
from src.api.insights_endpoints import TIER2_JOBS


def test_tier2_enqueue_and_stop():
    client = TestClient(app)
    rows = [{'row_index': 0, 'raw': {'process_name': 'cmd.exe', 'host': 'host1', 'verdict': 'suspicious'}}]
    resp = client.post('/api/v1/insights/tier2/enqueue', json={'rows': rows})
    assert resp.status_code == 200
    j = resp.json()
    job_id = j.get('job_id')
    assert job_id
    # wait a bit for worker to start
    time.sleep(0.2)
    status = client.get(f'/api/v1/insights/tier2/{job_id}/status').json()
    assert status.get('status') in ('queued', 'running', 'completed')
    # request stop (may be already completed, but endpoint should accept it)
    stop = client.post(f'/api/v1/insights/tier2/{job_id}/stop')
    assert stop.status_code == 200
    # Check registry entry for cancel_requested or final state
    job = TIER2_JOBS.get(job_id)
    assert job is not None
    assert job.get('status') in ('stopping', 'cancelled', 'completed', 'failed')

import time
from fastapi.testclient import TestClient
from src.api.app import create_app

# Use factory in test bodies or fixtures to avoid import-time side effects
app = create_app({'mode': 'test'})

# Ensure server module is imported so its @app routes are registered
import src.api.server  # noqa: F401 - side-effect: registers endpoints

from src.core.pipeline.stages import start_pipeline_run, snapshot

client = TestClient(app)


def test_pipeline_snapshot_happy_path():
    run_id = start_pipeline_run()
    # Run a small stage to ensure there's at least one entry
    from src.core.pipeline.stages import run_stage

    def _noop():
        return True

    run_stage(run_id, 'noop', _noop)
    resp = client.get(f'/api/v1/pipeline/run/{run_id}')
    assert resp.status_code == 200
    data = resp.json()
    assert data.get('run_id') == run_id
    assert 'stages' in data and isinstance(data['stages'], list)
    assert any(s.get('name') == 'noop' for s in data['stages'])


def test_pipeline_snapshot_missing():
    resp = client.get('/api/v1/pipeline/run/missing-run-12345')
    assert resp.status_code == 404

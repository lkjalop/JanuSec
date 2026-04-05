from fastapi.testclient import TestClient
import hashlib
import os

# Use the in-repo FastAPI app so tests don't depend on an external HTTP server.
from src.api.app import create_app
app = create_app({'mode': 'test'})

SHIM_PATH = os.path.join(os.path.dirname(__file__), '..', 'frontend', 'static', 'test_shims', 'csv_analyzer_shim.html')


def test_shim_served_ok():
    """Fast check: the test shim must be served at /static/test_shims/csv_analyzer_shim.html with HTTP 200 when mounted into the app."""
    client = TestClient(app)
    r = client.get('/static/test_shims/csv_analyzer_shim.html')
    assert r.status_code == 200, f"Shim not served (status={r.status_code})"


def test_shim_matches_disk():
    """Optional: assert the served content matches the on-disk shim to detect accidental replacement (helpful in CI)."""
    client = TestClient(app)
    r = client.get('/static/test_shims/csv_analyzer_shim.html')
    assert r.status_code == 200
    with open(SHIM_PATH, 'rb') as f:
        local = f.read()
    served = r.content
    assert hashlib.sha256(served).hexdigest() == hashlib.sha256(local).hexdigest(), "Served shim differs from disk copy"

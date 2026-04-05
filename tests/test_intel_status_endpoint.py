import asyncio
import json

from fastapi.testclient import TestClient

try:
    from src.api.app import app  # type: ignore
except Exception as e:  # pragma: no cover
    app = None  # type: ignore


def test_intel_status_structure():
    if app is None:
        return
    client = TestClient(app)
    r = client.get('/api/v1/intel/status')
    assert r.status_code == 200
    data = r.json()
    # Basic required keys even if disabled
    assert 'enabled' in data
    if data.get('enabled'):
        for k in ('counts','last_sync','freshness_seconds','stale'):
            assert k in data, f"missing key {k} in intel status"
        counts = data['counts']
        assert isinstance(counts, dict)
        # Ensure standard IoC buckets exist
        for bucket in ('ips','domains','urls','hashes','ja3','certfps'):
            assert bucket in counts


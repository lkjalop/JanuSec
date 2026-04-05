import json
import time
from src.api.dev_endpoints import router as dev_router
from src.api.runtime_state import get_file_batch_analysis, ServerRuntime
from src.api.dev_endpoints import dev_upload_sync, dev_review_score
from fastapi.testclient import TestClient
from src.api.app import app


def test_dev_upload_sync_seeds_batches():
    client = TestClient(app)
    # Ensure lite mode for test
    import os
    os.environ['PLATFORM_LITE_INIT'] = '1'
    csv = 'user,host,sha256\njoe,host1,hashA\n'
    r = client.post('/api/v1/dev/upload_sync', json={'csv': csv})
    assert r.status_code == 200
    data = r.json()
    assert 'sessions' in data
    sessions = data['sessions'] or []
    # verify that seeded batches exist in runtime
    batches = get_file_batch_analysis(None)
    for s in sessions:
        assert s in batches
        b = batches[s]
        assert 'files' in b and isinstance(b['files'], list)
        # check for enriched artifacts
        assert any('ja3' in f or 'ja3s' in f or 'tls_cert' in f for f in b['files'])


def test_dev_review_score_persists_review():
    client = TestClient(app)
    import os
    os.environ['PLATFORM_LITE_INIT'] = '1'
    # Create an incident via aggregator directly
    from src.incidents.aggregator import GLOBAL_INCIDENTS
    ev = {'event_id': 'evt-test', 'ts': int(time.time()), 'summary': 't'}
    inc = GLOBAL_INCIDENTS.ingest(ev, ['test_factor'])
    iid = inc['id']
    payload = {'incident_id': iid, 'reviewer': 'qa1', 'verdict': 'fp', 'note': 'not a threat'}
    r = client.post('/api/v1/dev/review_score', json=payload)
    assert r.status_code == 200
    d = r.json()
    assert d.get('status') == 'ok'
    # Incident should have the review attached
    stored = GLOBAL_INCIDENTS.incidents.get(iid)
    assert stored is not None
    assert 'reviews' in stored and any(rv['reviewer']=='qa1' for rv in stored['reviews'])

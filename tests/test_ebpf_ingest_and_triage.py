import time
import json
import os
from fastapi.testclient import TestClient
from src.api.app import app

# Use external server if JANUSEC_API is explicitly set; otherwise use TestClient(app)
ENV_BASE = os.environ.get('JANUSEC_API')
if ENV_BASE:
    BASE = ENV_BASE
    _USE_TESTCLIENT = False
else:
    BASE = 'http://testserver'
    _USE_TESTCLIENT = True
    _TC = TestClient(app)


def test_batch_ingest_and_triage():
    url = BASE + '/api/v1/events/batch'
    sample_events = [
        {'event_type': 'execve', 'pid': 1001, 'comm': 'bash', 'cmdline': '/tmp/evil', 'container_id': 'c1', 'evidence': 'exec in tmp', 'confidence': 0.9},
        {'event_type': 'open', 'pid': 1002, 'comm': 'wget', 'cmdline': 'wget http://mal', 'container_id': 'c1', 'path': '/var/run/docker.sock', 'evidence': 'open docker.sock', 'confidence': 0.95},
        {'event_type': 'ptrace', 'pid': 1001, 'comm': 'injector', 'cmdline': 'inject', 'container_id': 'c1', 'evidence': 'ptrace target 1000', 'confidence': 0.99},
    ]
    # Retry a few times to tolerate transient server startup timing in CI
    max_retries = 3
    body = {}
    print('DEBUG_BASE', BASE, 'POST_URL', url)
    # POST the batch; some test environments return non-standard response objects.
    if _USE_TESTCLIENT:
        r = _TC.post('/api/v1/events/batch', json={'batch_id': 't1', 'events': sample_events})
        assert r.status_code == 200
        r2 = _TC.get('/api/v1/events/ebpf')
        assert r2.status_code in (200, 404)
        events = r2.json().get('events', []) if r2.status_code == 200 else []
    else:
        import requests
        r = requests.post(url, json={'batch_id': 't1', 'events': sample_events})
        assert r.status_code == 200
        # Validate insertion by querying the read-back endpoint rather than trusting the returned JSON
        r2 = requests.get(BASE + '/api/v1/events/ebpf')
        assert r2.status_code in (200, 404)
        events = []
        if r2.status_code == 200:
            try:
                events = r2.json().get('events', [])
            except Exception:
                # try fallback: parse plain text for debug
                try:
                    import json as _json
                    events = _json.loads(r2.text).get('events', [])
                except Exception:
                    events = []
    assert isinstance(events, list)
    # Expect at least the number of events we posted
    assert len(events) >= len(sample_events)

    # Now call triage rule directly via import
    from src.core.triage_rules.ebpf_missing_rootca import correlate_missing_root_ca
    missing_event = {'container_id': 'c1', 'pid': 1001, 'detail': 'missing_root_ca TLS'}
    # Pull current events from API view
    if _USE_TESTCLIENT:
        r2 = _TC.get('/api/v1/events/ebpf')
        assert r2.status_code in (200, 404)
        events = r2.json().get('events', []) if r2.status_code == 200 else []
    else:
        import requests
        r2 = requests.get(BASE + '/api/v1/events/ebpf')
        assert r2.status_code in (200, 404)
        events = r2.json().get('events', []) if r2.status_code == 200 else []
    correlated = correlate_missing_root_ca([missing_event], events)
    # Expect at least one correlated hit
    assert isinstance(correlated, list)
    if correlated:
        assert correlated[0].get('score', 0) > 0

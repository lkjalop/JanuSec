import os
import time

from fastapi.testclient import TestClient

from src.api.dependencies import get_canonical_alert_ring
from src.api.server import app
client = TestClient(app)

# Force short dedup TTL
os.environ['ALERTS_API_KEYS'] = 'testkey'
os.environ['ALERT_DEDUP_TTL_SECONDS'] = '1'

BASE_EVENT = {
    'events': [
        {'id':'e1','host':'h1','proc_name':'powershell.exe','parent_proc':'winword.exe','dest_ip':'9.9.9.9'}
    ],
    'classify': True,
    'send_alerts': True,
    'include_rules': True
}

def test_dedup_suppression_and_expiry():
    # Some suites (test_adapter) import this module once and later mutate the
    # TTL env var. Force the short dedup + grace settings before each run so
    # the expectations remain stable regardless of prior imports.
    os.environ['ALERT_DEDUP_TTL_SECONDS'] = '1'
    os.environ['ALERT_DEDUP_GRACE_SECONDS'] = '0.25'
    ring, ring_lock, _ = get_canonical_alert_ring()
    with ring_lock:
        ring.clear()
    # First alert
    r1 = client.post('/api/v1/endpoints/log_batch', json=BASE_EVENT)
    assert r1.status_code == 200
    time.sleep(0.2)
    ring, ring_lock, _ = get_canonical_alert_ring()
    with ring_lock:
        assert len(ring) == 1
    # Duplicate inside TTL
    r2 = client.post('/api/v1/endpoints/log_batch', json=BASE_EVENT)
    time.sleep(0.2)
    ring, ring_lock, _ = get_canonical_alert_ring()
    with ring_lock:
        assert len(ring) == 1, 'dedup failed to suppress second alert'
    # Wait TTL expiry
    time.sleep(1.2)
    r3 = client.post('/api/v1/endpoints/log_batch', json=BASE_EVENT)
    time.sleep(0.2)
    ring, ring_lock, _ = get_canonical_alert_ring()
    with ring_lock:
        assert len(ring) == 2, 'alert not emitted after TTL expiry'

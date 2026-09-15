import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from src.api.server import _ALERT_RING, _ALERT_RING_LOCK, app
from src.api.dependencies import get_canonical_alert_ring

client = TestClient(app)

# Short TTL for fast test
os.environ['ALERT_DEDUP_TTL_SECONDS'] = '1'
os.environ['ALERTS_API_KEYS'] = 'testkey'

BASE_EVENT = {
    'events': [
        {'id': 'concur1', 'host': 'h-conc', 'proc_name': 'cmd.exe', 'parent_proc': 'explorer.exe'}
    ],
    'classify': True,
    'send_alerts': True,
    'include_rules': True
}


def _post_event():
    return client.post('/api/v1/endpoints/log_batch', json=BASE_EVENT)


def test_concurrent_dedup_suppression():
    ring, ring_lock, _ = get_canonical_alert_ring()
    with ring_lock:
        ring.clear()
    # fire two concurrent requests
    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(_post_event) for _ in range(2)]
        results = [f.result() for f in futures]
    for r in results:
        assert r.status_code == 200
    # small wait for any async background tasks
    time.sleep(0.5)
    with _ALERT_RING_LOCK:
        # exactly one alert should be present
        assert len(ring) == 1, f"expected 1 alert, got {len(ring)}"

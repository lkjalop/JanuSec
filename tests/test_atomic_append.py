import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from src.core.dedup.dedup_service import reset_for_tests
import src.api.alerts_endpoints as ae


def test_atomic_reserve_append():
    # enable trace for debugging if desired
    os.environ['ALERT_APPEND_TRACE'] = '1'
    os.environ['ALERT_APPEND_TRACE_PATH'] = 'tmp_debug_append_trace.log'

    # lightweight canonical ring replacement
    ring = []
    ring_lock = threading.Lock()
    ring_max = 10

    def _get_canonical():
        return (ring, ring_lock, ring_max)

    ae.get_canonical_alert_ring = _get_canonical

    reset_for_tests()

    def worker(i):
        ae.append_alert({'id': 'atomic1', 'ts': time.time(), 'tenant_id': 't1'})

    # run two concurrent appenders
    with ring_lock:
        ring.clear()

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(worker, i) for i in range(2)]
        [f.result() for f in futures]

    with ring_lock:
        ids = [str(item.get('id')) for item in ring if item.get('id')]
        assert len(set(ids)) == 1, f"expected single unique alert id, got ids={ids}"

    # cleanup env
    os.environ.pop('ALERT_APPEND_TRACE', None)
    os.environ.pop('ALERT_APPEND_TRACE_PATH', None)

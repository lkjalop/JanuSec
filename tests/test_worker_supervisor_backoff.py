import os
import time
import multiprocessing

from src.core.event_pipeline.worker_supervisor import get_supervisor
from src.core.event_pipeline.tests_support import crash_exit


def test_supervisor_restarts_on_worker_crash():
    # Enable supervisor via env for this test
    os.environ['ENABLE_SUPERVISOR'] = '1'
    from src.core.event_pipeline.worker_supervisor import reset_supervisor
    reset_supervisor()
    sup = get_supervisor(processes=1)
    try:
        sup.heartbeat_interval = 0.5
    except Exception:
        pass
    # Submit a task that kills the worker process
    try:
        sup.submit(crash_exit, (), timeout=3)
    except Exception:
        # submit may raise because child dies; that's acceptable
        pass
    # Allow time for supervisor probe + restart backoff
    time.sleep(2)
    health = sup.health()
    assert health.get('worker_count', 0) >= 1
    # Ensure supervisor recorded restart attempts (internal state)
    # Accessing protected member for test validation
    attempts = getattr(sup, '_restart_attempts', {})
    assert isinstance(attempts, dict)
    assert any(v > 0 for v in attempts.values())

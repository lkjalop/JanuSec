import os
import time

from src.core.event_pipeline.worker_supervisor import get_supervisor
from src.core.event_pipeline.tests_support import crash_exit


def test_restart_caps_limit():
    os.environ['ENABLE_SUPERVISOR'] = '1'
    os.environ['SUPERVISOR_RESTART_MAX_ATTEMPTS_PER_WORKER'] = '2'
    from src.core.event_pipeline.worker_supervisor import reset_supervisor
    reset_supervisor()
    sup = get_supervisor(processes=1)
    try:
        sup.heartbeat_interval = 0.2
    except Exception:
        pass
    # Crash worker multiple times
    for _ in range(3):
        try:
            sup.submit(crash_exit, (), timeout=2)
        except Exception:
            pass
        time.sleep(0.5)

    attempts = getattr(sup, '_restart_attempts', {})
    # ensure restart attempts were recorded and capped at >=2
    assert any(v >= 1 for v in attempts.values())
    assert max(attempts.values()) <= 2

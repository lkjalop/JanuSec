import os
import sys
import time
import json
import subprocess
import tempfile
import asyncio
import signal
import pytest

try:
    import redis
except Exception:
    redis = None

from src.api import insights_endpoints as ie


@pytest.mark.skipif(redis is None, reason='redis package not installed')
def test_redis_cancel_across_processes(monkeypatch, tmp_path):
    url = os.getenv('REDIS_URL')
    if not url:
        pytest.skip('REDIS_URL not set')
    try:
        from src.queue import redis_tier2
        redis_tier2.init(url)
    except Exception:
        pytest.skip('redis backend unavailable')

    # Start consumer in a subprocess that runs a short-lived consumer
    runner = [sys.executable, '-c', 'from src.queue.redis_consumer import consumer_loop; consumer_loop(run_seconds=10)']
    proc = subprocess.Popen(runner)
    try:
        # enqueue a long job
        job = {'rows': [{'row_index': i, 'raw': {'sha256': f'hash-{i}'}} for i in range(10)], 'pipeline_context': {}}
        loop = asyncio.get_event_loop()
        resp = loop.run_until_complete(ie.tier2_enqueue(job))
        job_id = resp.get('job_id')
        assert job_id

        # Give consumer a moment to pick up the job
        time.sleep(1)
        # Ask to stop the job
        loop.run_until_complete(ie.tier2_job_stop(job_id))

        # Wait a bit and assert job status is cancelled or stopping/completed
        time.sleep(2)
        status = loop.run_until_complete(ie.tier2_job_status(job_id))
        assert status.get('status') in ('cancelled', 'stopping', 'completed')
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        proc.wait(timeout=5)

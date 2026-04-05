import os
import asyncio
import pytest

try:
    import redis
except Exception:
    redis = None

from src.api import insights_endpoints as ie


@pytest.mark.skipif(redis is None, reason='redis package not installed')
def test_redis_enqueue_and_consume(monkeypatch, tmp_path):
    # Try to initialize redis client to REDIS_URL if provided, else skip
    url = os.getenv('REDIS_URL')
    if not url:
        pytest.skip('REDIS_URL not set')
    try:
        from src.queue import redis_tier2
        redis_tier2.init(url)
    except Exception:
        pytest.skip('redis backend unavailable')

    # Build a tiny job
    job = {
        'rows': [{'row_index': 0, 'raw': {'sha256': 'abc'}}],
        'pipeline_context': {}
    }

    # Call enqueue endpoint directly
    loop = asyncio.get_event_loop()
    resp = loop.run_until_complete(ie.tier2_enqueue(job))
    assert resp.get('status') == 'queued'
    job_id = resp.get('job_id')
    assert job_id

    # Start consumer loop for a short time
    from src.queue.redis_consumer import consumer_loop
    consumer_loop(run_seconds=2)

    status = loop.run_until_complete(ie.tier2_job_status(job_id))
    assert status.get('status') in ('completed', 'cancelled')

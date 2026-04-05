import os
import json
import time
import pytest

from src.core.redis_llm_queue import dequeue_batch

pytestmark = pytest.mark.integration


def _get_redis_client():
    try:
        import redis
    except Exception:
        return None
    url = os.getenv('REDIS_URL') or 'redis://127.0.0.1:6379/0'
    try:
        return redis.from_url(url)
    except Exception:
        return None


def test_dequeue_batch_integration_redis():
    client = _get_redis_client()
    if client is None:
        pytest.skip('Redis client library not available - set REDIS_URL to run integration')
    try:
        client.ping()
    except Exception:
        pytest.skip('Redis not reachable on REDIS_URL; skip integration')

    # Prepare: clear keys
    zkey = 'llm:priority'
    lkey = 'llm:tasks'
    try:
        client.delete(zkey)
        client.delete(lkey)
    except Exception:
        pass

    # Push two tasks with different priority payloads
    t1 = {'task_id': 't1', 'assessment_id': 'a1', 'payload': {'text': 'ransom encryptor'}}
    t2 = {'task_id': 't2', 'assessment_id': 'a1', 'payload': {'text': 'login event'}}
    client.rpush(lkey, json.dumps(t1))
    client.rpush(lkey, json.dumps(t2))
    # add zset entries to simulate enqueue_task behavior
    client.zadd(zkey, {json.dumps(t1): 10.0, json.dumps(t2): 80.0})

    # Call dequeue_batch and expect to receive up to 2 tasks
    tasks = dequeue_batch(batch_size=5, timeout=1)
    assert isinstance(tasks, list)
    # Ensure at least one of expected task ids present
    ids = {t.get('task_id') for t in tasks if isinstance(t, dict)}
    assert 't1' in ids or 't2' in ids

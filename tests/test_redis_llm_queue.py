import os
import json
import pytest

from src.core.redis_llm_queue import enqueue_task, dequeue_task, peek_per_assessment_queue
from src.core.redis_helpers import get_redis_client


@pytest.mark.skipif(not os.getenv('REDIS_URL'), reason='REDIS_URL not configured')
def test_enqueue_and_dequeue_roundtrip():
    client = get_redis_client()
    assert client is not None
    # flush test keys
    client.delete('llm:tasks')
    client.delete('llm:queue:test-assess')
    task = {'prompt': 'hello', 'payload': {'foo': 'bar'}}
    tid = enqueue_task('test-assess', task)
    assert tid is not None
    # peek per assessment
    items = peek_per_assessment_queue('test-assess', limit=10)
    assert any(it.get('task_id') == tid for it in items)
    # dequeue from global
    got = dequeue_task(timeout=2)
    assert got is not None
    assert got.get('task_id') == tid

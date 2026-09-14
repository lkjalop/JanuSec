#!/usr/bin/env python3
"""
Small helper that pushes batches of events into a Redis list for durable buffering.
Usage: python scripts/redis_enqueue_client.py
"""
import os
import json
import time
import random

REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
STREAM_NAME = os.getenv('STREAM_INGEST_NAME', 'ingest_stream')
GROUP_NAME = os.getenv('STREAM_INGEST_GROUP', 'ingest_group')

try:
    import redis
except Exception:
    redis = None


def make_event(i: int):
    return {
        'event_id': f'redis-stress-{int(time.time()*1000)}-{i}-{random.randint(0,9999)}',
        'proc_name': 'stress.exe',
        'cmdline': 'stress --test',
        'tenant_id': 'default',
        'factors': ['stress:test'],
    }


def push_batch(batch_size: int = 10):
    if not redis:
        print('redis library not installed. pip install redis')
        return
    r = redis.from_url(REDIS_URL)
    events = [make_event(i) for i in range(batch_size)]
    payload = json.dumps({'events': events, 'classify': True})
    # Use XADD into stream
    try:
        r.xadd(STREAM_NAME, {'data': payload})
        print(f'xadd batch size={batch_size} to {STREAM_NAME} at {REDIS_URL}')
    except Exception:
        # fall back to list push
        r.rpush('ingest_queue', payload)
        print(f'fallback rpush batch size={batch_size} to ingest_queue at {REDIS_URL}')


if __name__ == '__main__':
    for i in range(5):
        push_batch(10)
        time.sleep(0.2)

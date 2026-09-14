#!/usr/bin/env python3
"""
Background batch writer that pulls batches from Redis and forwards them to the ingestion HTTP endpoint.
- Uses BRPOP to pop items (blocking) and sends HTTP POST to /api/v1/ingest/batch
- Batches multiple queued items into a single request up to BATCH_MAX_ITEMS
- Performs simple exponential backoff on transient HTTP errors

Usage: python scripts/redis_batch_writer.py
Environment variables:
  REDIS_URL (default redis://localhost:6379/0)
  INGEST_QUEUE_NAME (default ingest_queue)
  INGEST_URL (default http://127.0.0.1:8000/api/v1/ingest/batch)

Note: This script intentionally keeps dependencies optional and will print instructions
if 'redis' or 'requests' libraries are missing.
"""
import os
import time
import json
import sys
from typing import List

REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
QUEUE_NAME = os.getenv('INGEST_QUEUE_NAME', 'ingest_queue')
INGEST_URL = os.getenv('INGEST_URL', 'http://127.0.0.1:8000/api/v1/ingest/batch')
BATCH_MAX_ITEMS = int(os.getenv('BATCH_MAX_ITEMS', '20'))
BRPOP_TIMEOUT = int(os.getenv('BRPOP_TIMEOUT', '5'))

try:
    import redis
except Exception:
    redis = None

try:
    import requests
except Exception:
    requests = None


def drain_batch(rclient, first_item, batch_max) -> List[dict]:
    items = []
    try:
        payload = json.loads(first_item)
    except Exception:
        # if stored as plain text, wrap
        payload = {'events': [first_item]}
    items.extend(payload.get('events') if isinstance(payload.get('events'), list) else [payload.get('events')])

    # try to accumulate more quickly without blocking
    while len(items) < batch_max:
        popped = rclient.rpop(QUEUE_NAME)
        if not popped:
            break
        try:
            p = json.loads(popped)
            events = p.get('events') if isinstance(p.get('events'), list) else [p.get('events')]
            items.extend(events)
        except Exception:
            items.append(popped)
    return items


def forward_batch(events: List[dict]) -> bool:
    if not requests:
        print('requests lib missing. pip install requests')
        return False
    data = {'events': events, 'classify': True}
    headers = {'Content-Type': 'application/json'}
    backoff = 1.0
    for attempt in range(5):
        try:
            resp = requests.post(INGEST_URL, json=data, headers=headers, timeout=10)
            if resp.status_code in (200, 201, 202):
                print(f'forwarded batch size={len(events)} status={resp.status_code}')
                return True
            elif 400 <= resp.status_code < 500:
                print(f'client error forwarding batch: {resp.status_code} {resp.text}')
                return True  # drop bad payloads
            else:
                print(f'server error {resp.status_code}, retrying')
        except Exception as e:
            print('network error forwarding batch:', e)
        time.sleep(backoff)
        backoff = min(backoff * 2, 10)
    return False


def run_loop():
    if not redis:
        print('redis library not installed. pip install redis')
        sys.exit(1)
    rclient = redis.from_url(REDIS_URL)
    print('connected to redis', REDIS_URL, 'queue=', QUEUE_NAME)
    while True:
        try:
            res = rclient.blpop(QUEUE_NAME, timeout=BRPOP_TIMEOUT)
            if not res:
                # no data, sleep shortly
                time.sleep(0.5)
                continue
            # res is tuple (queue, payload)
            _, payload = res
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8')
            events = drain_batch(rclient, payload, BATCH_MAX_ITEMS)
            if not events:
                continue
            ok = forward_batch(events)
            if not ok:
                # on failure, requeue the events as a single item at the head to preserve ordering
                try:
                    combined = json.dumps({'events': events})
                    rclient.lpush(QUEUE_NAME, combined)
                    print('requeued failed batch of size', len(events))
                except Exception as e:
                    print('failed to requeue:', e)
                    time.sleep(1)
        except KeyboardInterrupt:
            print('shutdown requested')
            break
        except Exception as e:
            print('worker error', e)
            time.sleep(1)


if __name__ == '__main__':
    run_loop()

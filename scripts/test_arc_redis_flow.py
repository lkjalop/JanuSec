"""Simple script to test ARC Redis queue delayed scheduling, backoff, and DLQ.

Usage:
  Set REDIS_URL environment variable before running.
  python scripts/test_arc_redis_flow.py

This script will:
- Connect to Redis
- Enqueue a sample job with req_id 'test-req-<ts>'
- Attempt to pop it (simulate worker), then force a failure by putting it into DLQ
- List DLQ, then call replay_by_req endpoint via HTTP to confirm re-enqueue.

Note: This script is a local test helper and uses the app's admin endpoints to replay.
"""
import os
import time
import json
import base64

try:
    import redis
except Exception:
    redis = None

if __name__ == '__main__':
    url = os.environ.get('REDIS_URL')
    if not url:
        print('REDIS_URL not set - aborting')
        raise SystemExit(1)
    if redis is None:
        print('redis python package not found. Install with pip install redis')
        raise SystemExit(1)
    r = redis.from_url(url, decode_responses=True)
    queue = os.getenv('ARC_VERIFY_QUEUE_KEY','arc:verify:queue')
    dlq = os.getenv('ARC_VERIFY_DLQ_KEY','arc:verify:dlq')
    req_id = f'test-req-{int(time.time())}'
    raw = b'This is a synthetic test email body for ARC testing.'
    job = {'req_id': req_id, 'raw': base64.b64encode(raw).decode('ascii'), 'raw_b64': True, 'attempts': 0, 'max_attempts': 3}
    payload = json.dumps({'job': job, 'ts': time.time()})
    print('Enqueueing job', req_id)
    r.lpush(queue, payload)
    print('Popped raw from queue (simulate worker pop):')
    popped = r.rpoplpush(queue, os.getenv('ARC_VERIFY_PROC_KEY','arc:verify:processing'))
    print('popped:', popped[:200])
    print('Simulating failure -> move to DLQ')
    r.lpush(dlq, popped)
    print('DLQ length now', r.llen(dlq))
    print('Listing first DLQ item (decoded snippet):')
    item = r.lindex(dlq, 0)
    obj = json.loads(item)
    job = obj.get('job', {})
    if job.get('raw_b64') and isinstance(job.get('raw'), str):
        print('raw sample:', base64.b64decode(job.get('raw')).decode('utf-8', errors='ignore')[:200])
    else:
        print('raw:', job.get('raw'))
    print('\nNow call the replay_by_req endpoint to re-enqueue (if your app is running locally)')
    api_key = os.environ.get('ADMIN_API_KEY') or os.environ.get('API_KEY') or 'devkey123'
    import requests
    try:
        resp = requests.post('http://127.0.0.1:8080/api/v1/admin/arc/dlq/replay_by_req', json={'req_id': req_id}, headers={'x-admin-key': api_key})
        print('replay_by_req status:', resp.status_code, resp.text[:400])
    except Exception as e:
        print('HTTP call failed (is app running locally?):', e)
    print('Done')

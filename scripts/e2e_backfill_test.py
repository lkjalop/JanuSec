import requests
import time
import sys

base = 'http://127.0.0.1:18081'
headers = {'x-api-key': 'devkey123'}

def safe_get(path):
    try:
        r = requests.get(base + path, headers=headers, timeout=5)
        return r.status_code, r.text
    except Exception as e:
        return 'ERR', str(e)

def safe_post(path, json=None):
    try:
        r = requests.post(base + path, headers=headers, json=json, timeout=10)
        return r.status_code, r.text
    except Exception as e:
        return 'ERR', str(e)

print('Checking OpenAPI...')
print(safe_get('/openapi.json'))

print('Creating assessment...')
status, text = safe_post('/api/v1/csv/deep_analyze', json={'rows': [['a','b']], 'cols': ['c1','c2']})
print('create ->', status, text)
if status != 200:
    print('Create failed; aborting')
    sys.exit(2)

try:
    aid = None
    body = None
    import json as _j
    body = _j.loads(text)
    aid = body.get('assessment_id') or body.get('id') or body.get('assessment')
except Exception:
    aid = None

print('Assessment ID:', aid)
if not aid:
    print('No assessment id found; aborting')
    sys.exit(3)

print('Starting auto_backfill...')
print(safe_post('/api/v1/csv/deep_analyze/auto_backfill', json={'assessment_id': aid}))

print('Sleeping 1s to allow job start...')
time.sleep(1)
print('Status:')
print(safe_get(f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/status'))

print('Stopping job...')
print(safe_post(f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/stop'))

print('Final status:')
print(safe_get(f'/api/v1/csv/deep_analyze/auto_backfill/{aid}/status'))

print('Done')

import requests
import json
import sys

host = 'http://127.0.0.1:11434'
paths = ['/', '/api/version', '/api/generate', '/v1/generate']

print('Probing host:', host)
for p in paths:
    url = host.rstrip('/') + p
    try:
        print('\nGET', url)
        r = requests.get(url, timeout=5)
        print('status', r.status_code)
        print('body preview:', (r.text or '')[:800])
    except Exception as e:
        print('GET error for', url, repr(e))

# Try POST to /api/generate
payload = {
    'model': 'llama3',
    'prompt': 'Hello from probe',
    'stream': False,
    'options': {'num_predict': 32},
}
try:
    url = host.rstrip('/') + '/api/generate'
    print('\nPOST', url, 'payload:', json.dumps(payload))
    r = requests.post(url, json=payload, timeout=10)
    print('POST status', r.status_code)
    try:
        print('POST json:', r.json())
    except Exception:
        print('POST body preview:', (r.text or '')[:2000])
except Exception as e:
    print('POST error', repr(e))

try:
    url = host.rstrip('/') + '/v1/generate'
    print('\nPOST', url, 'payload:', json.dumps(payload))
    r = requests.post(url, json=payload, timeout=10)
    print('POST status', r.status_code)
    try:
        print('POST json:', r.json())
    except Exception:
        print('POST body preview:', (r.text or '')[:2000])
except Exception as e:
    print('POST /v1 error', repr(e))

"""Integration smoke harness: post Sysmon, CloudTrail, Email, and LOLBIN events
and call the graph session builder to validate reconstruction.
"""
import os
import sys
import time
import json
from pprint import pprint
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from fastapi.testclient import TestClient

# Import the app
try:
    from src.api.app import app
except Exception as e:
    print('Failed to import app:', e)
    raise

client = TestClient(app)

# Discover ingest endpoints
INGEST_PATHS = []
for r in app.routes:
    p = getattr(r, 'path', '')
    if p and p.startswith('/api/v1/ingest'):
        INGEST_PATHS.append(p)
INGEST_PATHS = sorted(set(INGEST_PATHS))
print('Discovered ingest paths:', INGEST_PATHS)

# Example payloads
SYS_MON = {
    'event_id': 'sysmon-1',
    'ts': time.time(),
    'event_type': 'process_create',
    'host': 'host-1.example',
    'user': 'Alice',
    'process': 'cmd.exe',
    'command_line': 'cmd.exe /c whoami'
}

CLOUDTRAIL_EVENT = {
    'eventVersion': '1.05',
    'userIdentity': {'type': 'IAMUser', 'principalId': 'EX_PRINCIPAL_ID', 'arn': 'arn:aws:iam::123456789012:user/Alice'},
    'eventTime': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'eventName': 'CreateUser',
    'awsRegion': 'us-east-1',
    'sourceIPAddress': '203.0.113.5',
    'requestParameters': {},
}

EMAIL_SAMPLE = {
    'message_id': 'msg-1',
    'from': 'attacker@example.com',
    'to': ['victim@example.com'],
    'subject': 'Important update',
    'body': 'Please click the link',
    'ts': time.time(),
}

LOLBIN = {
    'event_id': 'lolbin-1',
    'process': 'powershell.exe',
    'command_line': 'powershell -NoProfile -EncodedCommand ...',
    'host': 'host-1.example',
    'ts': time.time()
}

samples = {
    'sysmon': SYS_MON,
    'cloudtrail': CLOUDTRAIL_EVENT,
    'email': EMAIL_SAMPLE,
    'lolbin': LOLBIN,
}

# Helper to post to best-match ingest endpoint
def post_sample(kind, payload):
    # find a path containing the kind or reasonable substitute
    candidates = [p for p in INGEST_PATHS if kind in p or ('cloud' in p and 'cloudtrail' in kind) or ('email' in p and 'mail' in p)]
    if not candidates and INGEST_PATHS:
        candidates = [INGEST_PATHS[0]]
    if not candidates:
        print('No ingest endpoints available; skipping', kind)
        return None
    path = candidates[0]
    print('Posting', kind, '->', path)
    headers = {'x-api-key': os.environ.get('API_KEY', 'devkey123')}
    r = client.post(path, json=payload, headers=headers)
    print('->', r.status_code, r.text[:200])
    return r

# Post samples
results = {}
for k, payload in samples.items():
    try:
        r = post_sample(k, payload)
        results[k] = {'status': r.status_code if r is not None else None, 'text': r.text if r is not None else None}
    except Exception as e:
        results[k] = {'error': str(e)}

print('\nIngest post results:')
pprint(results)

# Build a graph session with the posted session ids (best-effort)
build_payload = {
    'session_ids': ['batch-1', 'batch-2'],
    'correlate': True,
    'ewma': True,
}
print('\nCalling graph/session/build')
resp = client.post('/api/v1/graph/session/build', json=build_payload, headers={'x-api-key': os.environ.get('API_KEY','devkey123')})
print('build status', resp.status_code)
try:
    j = resp.json()
    print('build result keys:', list(j.keys()))
    pprint(j.get('summary') or j)
except Exception:
    print('build response not json')

print('\nDone')

"""
Integration + reconstruction check script
- Simulates ingestion of Sysmon, CloudTrail, Email, and LOLBIN events
- Posts events to unified ingestion endpoints and then calls graph session builder
- Reports summary and basic assertions

Usage: python scripts/integration_multi_domain_check.py
"""
from pathlib import Path
import json
import time
import sys
from fastapi.testclient import TestClient

# Ensure repo root is on sys.path so `src` imports work when running scripts
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Import app
try:
    from src.api.app import app
except Exception as e:
    print('ERROR importing app:', e)
    raise

client = TestClient(app)

# Small helper to post events to the unified ingest endpoint
def discover_ingest_paths():
    paths = {}
    for r in app.routes:
        p = getattr(r, 'path', '')
        if p and '/ingest' in p:
            # normalize
            key = p.lower()
            paths[key] = p
    return paths


def post_ingest(batch_id, events, prefer_path=None):
    payload = {'session_id': batch_id, 'events': events}
    # prefer supplied path, else try common ingest endpoints
    if prefer_path:
        r = client.post(prefer_path, json=payload, headers={'x-api-key': 'testkey123'})
        return r
    # fallback to discovered paths
    paths = discover_ingest_paths()
    # try common candidates in order
    candidates = ['/api/v1/ingest/sysmon', '/api/v1/ingest/cloudtrail', '/api/v1/ingest/email', '/api/v1/ingest', '/api/v1/unified/ingest']
    for c in candidates:
        if c in paths or True:
            try:
                r = client.post(c, json=payload, headers={'x-api-key': 'testkey123'})
                if r.status_code != 404:
                    return r
            except Exception:
                pass
    # last resort: try root ingest path
    try:
        r = client.post('/api/v1/ingest', json=payload, headers={'x-api-key': 'testkey123'})
        return r
    except Exception:
        class _R: status_code = 500; text = 'no-ingest-endpoints'
        return _R()

# Call graph session builder
def build_session(session_ids):
    payload = {'session_ids': session_ids, 'correlate': True, 'ewma': True}
    r = client.post('/api/v1/graph/session/build', json=payload, headers={'x-api-key': 'testkey123'})
    return r

# Synthetic events
def make_sysmon_event(ts, src='C:\\\\Windows\\System32\\cmd.exe', user='DOMAIN\\user1', host='host-1'):
    return {'type': 'sysmon', 'ts': ts, 'host': host, 'user': user, 'process': src, 'cmdline': 'cmd /c whoami'}

def make_cloudtrail_event(ts, user='arn:aws:iam::123456789012:user/Alice', ip='3.3.3.3'):
    return {'type': 'cloudtrail', 'ts': ts, 'eventName': 'ConsoleLogin', 'userIdentity': user, 'sourceIPAddress': ip}

def make_email_event(ts, from_addr='badguy@example.com', to='user@example.com', subject='Important'): 
    return {'type': 'email', 'ts': ts, 'from': from_addr, 'to': to, 'subject': subject, 'message_id': 'mid-'+str(int(ts))}

def make_lolbin_event(ts, binary='regsvr32.exe', cmdline='regsvr32 /s /n /u /i:someurl dll'): 
    return {'type': 'lolbin', 'ts': ts, 'binary': binary, 'cmdline': cmdline}


def run_once():
    now = int(time.time())
    # Create batches for multiple domains
    batch_sys = 'batch-sysmon-1'
    batch_cloud = 'batch-cloudtrail-1'
    batch_email = 'batch-email-1'
    batch_lol = 'batch-lol-1'

    # Create events
    sys_events = [make_sysmon_event(now-10*i, host='host-1') for i in range(3)]
    cloud_events = [make_cloudtrail_event(now-5*i, ip='3.3.3.'+str(10+i)) for i in range(3)]
    email_events = [make_email_event(now-2*i, from_addr='phish'+str(i)+'@evil.test') for i in range(2)]
    lol_events = [make_lolbin_event(now, binary='regsvr32.exe')]

    print('Posting sysmon batch...')
    r = post_ingest(batch_sys, sys_events)
    print('->', r.status_code, r.text[:200])

    print('Posting cloudtrail batch...')
    r = post_ingest(batch_cloud, cloud_events)
    print('->', r.status_code, r.text[:200])

    print('Posting email batch...')
    r = post_ingest(batch_email, email_events)
    print('->', r.status_code, r.text[:200])

    print('Posting lolbin batch...')
    r = post_ingest(batch_lol, lol_events)
    print('->', r.status_code, r.text[:200])

    print('Building session...')
    r = build_session([batch_sys, batch_cloud, batch_email, batch_lol])
    print('Build status:', r.status_code)
    try:
        data = r.json()
    except Exception:
        print('Build response not JSON:', r.text)
        return False
    # basic checks
    print('Summary keys:', list(data.keys()))
    summ = data.get('summary') or data.get('graph') or data
    print('Summary snippet:', json.dumps(summ)[:800])

    # Basic success criteria: a summary object with 'factors' and 'verdict' or similar
    if isinstance(data, dict) and ('summary' in data or 'verdict' in data or 'factors' in data):
        print('Reconstruction returned expected keys')
        return True
    print('Unexpected build payload')
    return False

if __name__ == '__main__':
    ok = run_once()
    print('OK' if ok else 'FAIL')

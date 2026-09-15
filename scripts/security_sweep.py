#!/usr/bin/env python3
"""
Run a lightweight security/resilience sweep against the local API.
- Check admin/flags endpoint (unauthenticated then with a dummy token header)
- List DLQ entries
- Send repeated identical endpoint events (dedup soak) and check alerts_emitted
- Burst ingest a moderate number of events to look for 429/503 and observe buffer_size

This script is conservative and safe for a local dev instance.
"""
from __future__ import annotations
import json, time
from urllib import request, error

API = 'http://localhost:8080'


def http_get(path: str, headers: dict | None = None, timeout: float = 8.0) -> tuple[int, str]:
    url = API + path
    req = request.Request(url, method='GET')
    if headers:
        for k,v in headers.items(): req.add_header(k,v)
    try:
        with request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode('utf-8')
    except error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return 0, str(e)


def http_post(path: str, payload: dict, headers: dict | None = None, timeout: float = 10.0) -> tuple[int, str]:
    url = API + path
    data = json.dumps(payload).encode('utf-8')
    req = request.Request(url, data=data, method='POST')
    req.add_header('Content-Type','application/json')
    if headers:
        for k,v in headers.items(): req.add_header(k,v)
    try:
        with request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode('utf-8')
    except error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return 0, str(e)


def probe_admin_flags():
    print('\n[admin.flags] unauthenticated')
    code, body = http_get('/api/v1/admin/flags')
    print('status:', code)
    if code == 401 or code == 403:
        print('deny-by-default enforced for admin flags (expected).')
    else:
        print('response body (truncated):', body[:400])

    print('\n[admin.flags] with dummy token header')
    code, body = http_get('/api/v1/admin/flags', headers={'Authorization':'Bearer dummy'})
    print('status with Authorization: ', code)
    print('body (truncated):', body[:400])


def list_dlq():
    print('\n[dlq.list]')
    code, body = http_get('/api/v1/dlq')
    print('status', code)
    print('body (truncated):', body[:800])


def dedup_soak():
    print('\n[dedup.soak] Sending 5 identical events within dedup TTL')
    payload = {
        'events': [
            {
                'id': 'dup-event-1',
                'host': 'soak-host',
                'process': {'name':'powershell.exe','parent':'winword.exe','cmd':'-nop -w hidden -enc AAAA'},
                'details': {'lolbin': True}
            }
        ],
        'classify': True,
        'include_rules': True,
        'send_alerts': True
    }
    for i in range(5):
        code, body = http_post('/api/v1/endpoints/log_batch', payload)
        print(f'  run {i+1}: status={code} body=', body.strip()[:200])
        time.sleep(1)


def ingest_burst(n=80):
    print(f'\n[ingest.burst] Sending {n} lightweight events to check backpressure')
    events = []
    now = int(time.time()*1000)
    for i in range(n):
        events.append({'id': f'burst-{now}-{i}', 'host': f'burst-host', 'process': {'name':'cmd.exe','parent':'excel.exe','cmd':'/c whoami'}, 'details':{}})
    payload = {'events': events, 'classify': False, 'include_rules': False, 'send_alerts': False}
    code, body = http_post('/api/v1/endpoints/log_batch', payload)
    print('status', code)
    print('response (truncated):', body[:400])


if __name__ == '__main__':
    print('Starting light security/resilience sweep against', API)
    probe_admin_flags()
    list_dlq()
    dedup_soak()
    ingest_burst(80)
    print('\nSweep complete.')

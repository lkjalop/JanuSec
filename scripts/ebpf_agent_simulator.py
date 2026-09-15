#!/usr/bin/env python3
"""
Simple eBPF agent simulator that POSTs normalized events to the local API.
"""
import requests
import time
import uuid
import os
import json
import hmac
import hashlib

API_URL = os.environ.get('JANUSEC_API', 'http://127.0.0.1:8080')
BATCH_URL = API_URL.rstrip('/') + '/api/v1/events/batch'
HMAC_SECRET = os.environ.get('EBPF_INGEST_HMAC_SECRET')

SCENARIOS = {
    'exec_tmp': [
        {
            'event_type': 'execve',
            'pid': 1201,
            'ppid': 1,
            'comm': 'bash',
            'cmdline': '/tmp/evil.sh',
            'container_id': 'c1',
            'k8s_pod': 'web-1',
            'k8s_ns': 'prod',
            'path': '/tmp/evil.sh',
            'evidence': 'execve from /tmp',
            'confidence': 0.85,
        },
    ],
    'docker_sock': [
        {
            'event_type': 'open',
            'pid': 2302,
            'ppid': 1,
            'comm': 'wget',
            'cmdline': 'wget http://mal',
            'container_id': 'c1',
            'k8s_pod': 'web-1',
            'k8s_ns': 'prod',
            'path': '/var/run/docker.sock',
            'evidence': 'open docker.sock',
            'confidence': 0.95,
        },
    ],
    'ptrace_inject': [
        {
            'event_type': 'ptrace',
            'pid': 1801,
            'ppid': 1,
            'comm': 'injector',
            'cmdline': 'inject --pid 1800',
            'container_id': 'c1',
            'k8s_pod': 'web-1',
            'k8s_ns': 'prod',
            'evidence': 'ptrace target 1800',
            'confidence': 0.99,
        },
    ],
    'container_escape': [
        {
            'event_type': 'execve',
            'pid': 1901,
            'ppid': 1,
            'comm': 'mount',
            'cmdline': 'mount -t proc proc /host/proc',
            'container_id': 'c1',
            'k8s_pod': 'web-1',
            'k8s_ns': 'prod',
            'path': '/bin/mount',
            'evidence': 'host namespace mount attempt',
            'confidence': 0.9,
        },
    ],
}


def _build_payload(events):
    batch_id = str(uuid.uuid4())
    custody_blob = json.dumps({'batch_id': batch_id, 'events': events}, sort_keys=True, separators=(',', ':'))
    custody_hash = hashlib.sha256(custody_blob.encode('utf-8')).hexdigest()
    return {
        'batch_id': batch_id,
        'events': events,
        'custody': {
            'hash_algo': 'sha256',
            'custody_hash': custody_hash,
            'signed_at': int(time.time()),
        },
    }


def _signature(payload):
    if not HMAC_SECRET:
        return None
    body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    return hmac.new(HMAC_SECRET.encode('utf-8'), body, hashlib.sha256).hexdigest()

if __name__ == '__main__':
    scenario = os.environ.get('EBPF_SIM_SCENARIO', 'all').strip().lower()
    if scenario == 'all':
        events = []
        for evs in SCENARIOS.values():
            events.extend(evs)
    else:
        events = SCENARIOS.get(scenario, [])
    payload = _build_payload(events)
    body = json.dumps(payload, separators=(',', ':'))
    headers = {'Content-Type': 'application/json'}
    sig = _signature(payload)
    if sig:
        headers['X-Signature'] = sig
    print('Posting to', BATCH_URL, 'events', len(events), 'scenario', scenario)
    r = requests.post(BATCH_URL, data=body, headers=headers)
    print(r.status_code, r.text)

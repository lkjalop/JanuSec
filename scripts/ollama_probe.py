#!/usr/bin/env python3
"""Probe local Ollama endpoints and print results."""
import os
import requests

def safe_get(url, timeout=5):
    try:
        r = requests.get(url, timeout=timeout)
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)

def safe_post(url, json=None, timeout=120):
    try:
        r = requests.post(url, json=json, timeout=timeout)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return None, str(e)

def main():
    host = os.environ.get('OLLAMA_HOST', 'http://127.0.0.1:11434')
    print('OLLAMA_HOST ->', host)
    v_status, v_text = safe_get(host.rstrip('/') + '/api/version')
    print('/api/version ->', v_status)
    print(v_text[:1000])

    m_status, m_text = safe_get(host.rstrip('/') + '/v1/models')
    print('/v1/models ->', m_status)
    try:
        import json
        print(json.dumps(json.loads(m_text), indent=2)[:2000])
    except Exception:
        print(m_text[:1000])

    # Try multiple generate attempts with different models
    gen_url = host.rstrip('/') + '/api/generate'
    candidates = [os.environ.get('OLLAMA_MODEL', 'llama3:8b'), 'llama2:7b', 'llama1:3b']
    for model in candidates:
        if not model:
            continue
        payload = {'model': model, 'prompt': 'Hello', 'max_tokens': 8}
        print('\nPOST', gen_url, payload)
        for attempt in range(3):
            print('Attempt', attempt+1)
            g_status, g_text = safe_post(gen_url, json=payload, timeout=int(os.environ.get('OLLAMA_TIMEOUT_SECONDS', '120')))
            print('/api/generate ->', g_status)
            print(str(g_text)[:2000])
            if g_status:
                break

if __name__ == '__main__':
    main()
"""Probe local Ollama-like server for usable generate endpoint and payload shape.

Attempts several known endpoints and JSON shapes, logs responses, and writes
`sim_reports/ollama_probe.json` with results.
"""
import requests
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'sim_reports'
OUT.mkdir(exist_ok=True)

HOST = 'http://localhost:11434'

tests = [
    {'path': '/api/generate', 'body': {'model':'llama3:8b','prompt':'test','max_tokens':10}},
    {'path': '/v1/generate', 'body': {'model':'llama3:8b','prompt':'test','max_tokens':10}},
    {'path': '/generate', 'body': {'model':'llama3:8b','prompt':'test','max_tokens':10}},
    # alternate shape
    {'path': '/api/generate', 'body': {'prompt':'test','model':'llama3:8b','max_tokens':10}},
    {'path': '/v1/generate', 'body': {'prompt':'test','model':'llama3:8b','max_tokens':10}},
    {'path': '/api/generate', 'body': {'messages':[{'role':'user','content':'test'}], 'model':'llama3:8b'}},
]

results = []
for t in tests:
    url = HOST + t['path']
    try:
        r = requests.post(url, json=t['body'], timeout=6)
        results.append({'url': url, 'code': r.status_code, 'text': r.text[:200]})
    except Exception as e:
        results.append({'url': url, 'err': str(e)})

OUT.joinpath('ollama_probe.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
print('Wrote sim_reports/ollama_probe.json')

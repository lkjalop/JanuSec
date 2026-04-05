"""Invoke local Ollama endpoints (try several candidate paths), save raw response,
and write a simple Tier1-style JSON to data/tier1_sample_response.json.
"""
import requests
import json
from pathlib import Path
import sys

HOST = 'http://127.0.0.1:11434'
MODEL = 'llama3:8b'
OUT_DIR = Path('data')
OUT_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUT = OUT_DIR / 'ollama_raw_response.json'
TIER_OUT = OUT_DIR / 'tier1_sample_response.json'

PAYLOAD = {
    'model': MODEL,
    'prompt': 'You are a SOC analyst. Provide a concise triage summary for: rundll32.exe on host WKS-OLLAMA. Provide WHAT IS IT / EXPLOITABILITY / WHAT TO DO / CONCISE PLAYBOOK.',
    'stream': False,
    'options': {'num_predict': 128}
}

def try_endpoints():
    candidates = ['/api/generate', '/v1/generate', '/v1/predictions', '/generate']
    session = requests.Session()
    for p in candidates:
        url = HOST.rstrip('/') + p
        try:
            r = session.post(url, json=PAYLOAD, timeout=8)
        except Exception as e:
            print('ERR', url, type(e).__name__, e)
            continue
        try:
            text = r.text
            print('TRY', url, 'status', r.status_code)
            try:
                j = r.json()
            except Exception:
                j = {'text': text}
            return url, r.status_code, j
        except Exception as e:
            print('PARSE ERR', url, e)
            continue
    return None, None, None

def wrap_tier1(raw_json):
    # Extract text if possible
    text = None
    model = MODEL
    if isinstance(raw_json, dict):
        # common shapes
        if 'response' in raw_json:
            text = raw_json.get('response')
        elif 'output' in raw_json:
            text = raw_json.get('output')
        elif 'results' in raw_json:
            text = json.dumps(raw_json.get('results'))
        else:
            # try nested
            for v in raw_json.values():
                if isinstance(v, str) and len(v) > 10:
                    text = v
                    break
    if not text:
        text = json.dumps(raw_json)[:4000]

    payload = {
        'text': text,
        'insight_type': 'tier1',
        'estimated_cost': 0.01,
        'model': model,
        'payload': {
            'metadata': {'model_version': 'ollama-invoke', 'confidence_score': 0.8},
            'raw_summary': text,
        }
    }
    return payload

def main():
    url, status, j = try_endpoints()
    if url is None:
        print('No endpoint succeeded')
        return 2
    RAW_OUT.write_text(json.dumps({'url': url, 'status': status, 'response': j}, indent=2))
    tier = wrap_tier1(j)
    TIER_OUT.write_text(json.dumps(tier, indent=2))
    print('Saved raw ->', RAW_OUT)
    print('Saved tier1 ->', TIER_OUT)
    return 0

if __name__ == '__main__':
    sys.exit(main())

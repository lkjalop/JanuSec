"""Brute-force probe local Ollama endpoints and payload shapes until a generation succeeds.
Saves successful raw response to data/ollama_success.json and a wrapped tier1 JSON to data/tier1_sample_response.json.
"""
import requests
import json
from pathlib import Path
import sys

HOST = 'http://127.0.0.1:11434'
MODEL = 'llama3:8b'
OUT_DIR = Path('data')
OUT_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUT = OUT_DIR / 'ollama_success.json'
TIER_OUT = OUT_DIR / 'tier1_sample_response.json'

paths = [
    '/api/generate', '/v1/generate', '/v1/predictions', '/api/predict', '/generate',
    '/v1/models/{model}/predict', '/v1/models/{model}/generate', '/api/models/{model}/predict', '/api/models/{model}/generate',
    '/v1/models/{model}/infer', '/v1/models/{model}/completions', '/completions', '/v1/completions'
]

def make_payload_variants(prompt_text):
    return [
        {'model': MODEL, 'prompt': prompt_text, 'stream': False, 'options': {'num_predict': 128}},
        {'model': MODEL, 'input': prompt_text},
        {'model': MODEL, 'inputs': [prompt_text]},
        {'model': MODEL, 'messages': [{'role': 'user', 'content': prompt_text}]},
        {'prompt': prompt_text, 'model': MODEL},
        {'text': prompt_text, 'model': MODEL},
        {'prompt': {'text': prompt_text}, 'model': MODEL},
    ]

def extract_text_from_response(r):
    # Try common keys
    if isinstance(r, str):
        return r
    if isinstance(r, dict):
        for k in ('response','output','text','result','generated_text','content'):
            if k in r and isinstance(r[k], (str, list, dict)):
                val = r[k]
                if isinstance(val, str):
                    return val
                try:
                    return json.dumps(val)
                except Exception:
                    continue
        # OpenAI-like
        if 'choices' in r and isinstance(r['choices'], list) and r['choices']:
            c = r['choices'][0]
            if isinstance(c, dict):
                if 'text' in c and isinstance(c['text'], str):
                    return c['text']
                if 'message' in c and isinstance(c['message'], dict) and 'content' in c['message']:
                    return c['message']['content']
        # nested search
        for v in r.values():
            if isinstance(v, str) and len(v) > 10:
                return v
    return None

def try_endpoints():
    prompt = 'You are a SOC analyst. Provide a concise triage summary for: rundll32.exe on host WKS-OLLAMA. WHAT IS IT / EXPLOITABILITY / WHAT TO DO / CONCISE PLAYBOOK.'
    session = requests.Session()
    session.headers.update({'User-Agent': 'ollama-probe/1.0'})
    for p in paths:
        path = p.format(model=MODEL)
        url = HOST.rstrip('/') + path
        for payload in make_payload_variants(prompt):
            try:
                r = session.post(url, json=payload, timeout=8)
            except Exception as e:
                print('ERR', url, type(e).__name__, e)
                continue
            print('TRY', url, 'status', r.status_code)
            try:
                j = r.json()
            except Exception:
                j = {'text': r.text}
            text = extract_text_from_response(j)
            if r.status_code == 200 and text:
                print('SUCCESS', url)
                RAW_OUT.write_text(json.dumps({'url': url, 'status': r.status_code, 'response': j}, indent=2))
                tier = {
                    'text': text,
                    'insight_type': 'tier1',
                    'estimated_cost': 0.02,
                    'model': MODEL,
                    'payload': {'metadata': {'model_version': 'ollama-detected'}, 'raw_summary': text}
                }
                TIER_OUT.write_text(json.dumps(tier, indent=2))
                return True
            else:
                # save debug sample of failed attempt (rotate)
                debug = OUT_DIR / f'ollama_debug_{abs(hash(url+json.dumps(payload)))%10000}.json'
                try:
                    debug.write_text(json.dumps({'url': url, 'status': r.status_code, 'response': j}, indent=2))
                except Exception:
                    pass
    return False

def main():
    ok = try_endpoints()
    if ok:
        print('Found working endpoint; saved to', RAW_OUT, TIER_OUT)
        return 0
    print('No working endpoint found with current candidates')
    return 2

if __name__ == '__main__':
    sys.exit(main())

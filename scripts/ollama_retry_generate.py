"""Retry calling local Ollama /api/generate with a string prompt until we get a non-empty response.
Saves raw response to data/ollama_success.json and a wrapped Tier1 JSON to data/tier1_sample_response.json.
"""
import requests
import time
import json
from pathlib import Path
import sys

HOST = 'http://127.0.0.1:11434'
ENDPOINT = '/api/generate'
MODEL = 'llama3:8b'
OUT_DIR = Path('data')
OUT_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUT = OUT_DIR / 'ollama_success.json'
TIER_OUT = OUT_DIR / 'tier1_sample_response.json'

PROMPT = (
    "You are a SOC analyst performing FAST TRIAGE. Follow the schema WHAT IS IT / EXPLOITABILITY / WHAT TO DO / "
    "CONCISE PLAYBOOK (20-40 lines).\nProcess: rundll32.exe\nHost: WKS-OLLAMA\nVerdict: SUSPICIOUS\nSignals: unsigned_executable,lolbin\n"
)

def try_generate(timeout=60):
    url = HOST.rstrip('/') + ENDPOINT
    payload = {'model': MODEL, 'prompt': PROMPT, 'stream': False, 'options': {'num_predict': 256}}
    try:
        r = requests.post(url, json=payload, timeout=timeout)
    except Exception as e:
        return None, f'ERR {type(e).__name__} {e}'
    try:
        j = r.json()
    except Exception:
        j = {'text': r.text}
    return j, None

def extract_text(j):
    if not j:
        return None
    if isinstance(j, dict):
        for k in ('response','output','text'):
            v = j.get(k)
            if isinstance(v, str) and v.strip():
                return v
        # try nested
        if 'results' in j and isinstance(j['results'], list) and j['results']:
            return json.dumps(j['results'])
    if isinstance(j, str) and j.strip():
        return j
    return None

def main():
    attempts = 8
    delay = 2
    for i in range(attempts):
        print(f'Attempt {i+1}/{attempts}...')
        j, err = try_generate(timeout=60)
        if err:
            print('call error', err)
        else:
            text = extract_text(j)
            # If response present and non-empty, save and exit
            if text:
                RAW_OUT.write_text(json.dumps({'url': HOST+ENDPOINT, 'response': j}, indent=2))
                tier = {'text': text, 'insight_type': 'tier1', 'estimated_cost': 0.02, 'model': MODEL, 'payload': {'metadata': {'model_version': 'ollama-live'}, 'raw_summary': text}}
                TIER_OUT.write_text(json.dumps(tier, indent=2))
                print('Success, saved outputs')
                return 0
            else:
                # Inspect done_reason or empty response; if load, wait longer
                try:
                    if isinstance(j, dict) and j.get('done_reason') == 'load':
                        print('Model loading, waiting...')
                        time.sleep(max(delay, 5))
                        delay *= 2
                        continue
                except Exception:
                    pass
                print('Empty response, will retry after', delay, 's')
        time.sleep(delay)
        delay = min(delay * 2, 30)
    print('No successful response after retries')
    return 2

if __name__ == '__main__':
    sys.exit(main())

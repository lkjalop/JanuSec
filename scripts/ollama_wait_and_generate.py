"""Wait for Ollama model to become ready and request a generation, handling load delays.
Saves raw response to data/ollama_success.json and a wrapped Tier1 JSON to data/tier1_sample_response.json.
"""
import requests
import time
import json
from pathlib import Path
import sys

HOST = 'http://127.0.0.1:11434'
MODEL = 'llama3:8b'
ENDPOINT = '/api/generate'
OUT_DIR = Path('data')
OUT_DIR.mkdir(parents=True, exist_ok=True)
RAW_OUT = OUT_DIR / 'ollama_success.json'
TIER_OUT = OUT_DIR / 'tier1_sample_response.json'

def get_version():
    try:
        r = requests.get(HOST + '/api/version', timeout=3)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def list_models():
    try:
        r = requests.get(HOST + '/v1/models', timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def try_generate(timeout=120):
    url = HOST.rstrip('/') + ENDPOINT
    prompt = (
        "You are a SOC analyst performing FAST TRIAGE. Follow the schema WHAT IS IT / EXPLOITABILITY / WHAT TO DO / "
        "CONCISE PLAYBOOK (20-40 lines).\nProcess: rundll32.exe\nHost: WKS-OLLAMA\nVerdict: SUSPICIOUS\nSignals: unsigned_executable,lolbin\n"
    )
    payload = {'model': MODEL, 'prompt': prompt, 'stream': False, 'options': {'num_predict': 256}}
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
        # common keys
        for k in ('response','output','text'):
            v = j.get(k)
            if isinstance(v, str) and v.strip():
                return v
        # openai-like
        if 'choices' in j and isinstance(j['choices'], list) and j['choices']:
            c = j['choices'][0]
            if isinstance(c, dict):
                if 'text' in c and isinstance(c['text'], str) and c['text'].strip():
                    return c['text']
                if 'message' in c and isinstance(c['message'], dict) and 'content' in c['message'] and isinstance(c['message']['content'], str):
                    return c['message']['content']
        # fallback: search for long string values
        for v in j.values():
            if isinstance(v, str) and len(v.strip()) > 20:
                return v
    if isinstance(j, str) and j.strip():
        return j
    return None

def main():
    total_wait = 600  # seconds
    start = time.time()
    attempt = 0
    backoff = 2
    # show version and models early
    ver = get_version()
    if ver:
        print('Ollama version:', ver)
    models = list_models()
    if models:
        print('models:', models)
    while time.time() - start < total_wait:
        attempt += 1
        print(f'Generate attempt {attempt}...')
        j, err = try_generate(timeout=120)
        if err:
            print('call error', err)
            # if connection refused or timeout, wait a bit
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)
            continue
        # inspect result
        # if dict and contains done_reason load or empty response, wait longer
        try:
            if isinstance(j, dict) and j.get('done_reason') == 'load':
                print('Model reported loading; waiting and retrying')
                time.sleep(5)
                continue
        except Exception:
            pass
        text = extract_text(j)
        if text:
            RAW_OUT.write_text(json.dumps({'url': HOST + ENDPOINT, 'response': j}, indent=2))
            tier = {'text': text, 'insight_type': 'tier1', 'estimated_cost': 0.02, 'model': MODEL, 'payload': {'metadata': {'model_version': 'ollama-live'}, 'raw_summary': text}}
            TIER_OUT.write_text(json.dumps(tier, indent=2))
            print('Success: saved outputs')
            return 0
        else:
            print('No text in response; saving debug and retrying')
            # save debug
            debug = OUT_DIR / f'ollama_debug_attempt_{attempt}.json'
            try:
                debug.write_text(json.dumps({'attempt': attempt, 'response': j}, indent=2))
            except Exception:
                pass
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)
    print('Timed out waiting for model to produce text')
    return 2

if __name__ == '__main__':
    sys.exit(main())

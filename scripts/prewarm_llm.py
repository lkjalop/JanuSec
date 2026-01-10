#!/usr/bin/env python3
"""CLI helper to call the app's LLM prewarm endpoint.

Usage:
  python scripts/prewarm_llm.py --host http://localhost:8080 --model llama3:8b --tokens 8

Reads API key from env `API_KEY` or `LOCAL_API_KEY` or defaults to `devkey123`.
"""
import argparse
import os
import sys
import requests


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--host', default=os.environ.get('PREWARM_HOST', 'http://localhost:8080'))
    p.add_argument('--model', default=os.environ.get('OLLAMA_MODEL'))
    p.add_argument('--tokens', type=int, default=int(os.environ.get('OLLAMA_PREWARM_TOKENS', '8')))
    p.add_argument('--api-key', default=os.environ.get('API_KEY') or os.environ.get('LOCAL_API_KEY') or 'devkey123')
    args = p.parse_args()

    url = args.host.rstrip('/') + '/api/v1/llm/prewarm'
    payload = {'num_predict': args.tokens}
    if args.model:
        payload['model'] = args.model
    headers = {'x-api-key': args.api_key, 'content-type': 'application/json'}
    print(f"Calling prewarm endpoint {url} with model={args.model} tokens={args.tokens}")
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=30)
        print('status', r.status_code)
        try:
            print(r.json())
        except Exception:
            print(r.text[:1000])
        return 0
    except Exception as e:
        print('prewarm failed:', e)
        return 2


if __name__ == '__main__':
    sys.exit(main())

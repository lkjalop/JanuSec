#!/usr/bin/env python3
import json
import urllib.request
import urllib.error
import os

BASE = os.environ.get('PLAYWRIGHT_BASE_URL', 'http://localhost:8080')
NAME = 'purview'
API_KEY = os.environ.get('API_KEY', 'devkey123')

def do_post():
    url = f"{BASE}/api/v1/admin/connectors/config/{NAME}"
    data = json.dumps({'config': {'test_field': 'playwright-test'}}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json', 'x-api-key': API_KEY}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            b = resp.read()
            print('POST status', resp.status)
            try:
                print('POST body:', json.loads(b.decode('utf-8')))
            except Exception:
                print('POST raw:', b.decode('utf-8', errors='replace'))
    except urllib.error.HTTPError as e:
        print('POST failed', e.code, e.read().decode())
    except Exception as e:
        print('POST exception', e)

def do_get():
    url = f"{BASE}/api/v1/admin/connectors/config/{NAME}"
    req = urllib.request.Request(url, headers={'x-api-key': API_KEY}, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            b = resp.read()
            print('GET status', resp.status)
            try:
                print('GET body:', json.loads(b.decode('utf-8')))
            except Exception:
                print('GET raw:', b.decode('utf-8', errors='replace'))
    except urllib.error.HTTPError as e:
        print('GET failed', e.code, e.read().decode())
    except Exception as e:
        print('GET exception', e)

if __name__ == '__main__':
    print('Posting config...')
    do_post()
    print('\nFetching config...')
    do_get()
    # Show file contents
    cfg_path = os.environ.get('CONNECTORS_CONFIG_PATH', os.path.join('data','connectors_configs.json'))
    print('\nLocal file:', cfg_path)
    try:
        with open(cfg_path,'r',encoding='utf-8') as f:
            print(f.read())
    except Exception as e:
        print('Failed to read local config file:', e)

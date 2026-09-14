import os, importlib, json, time, types
os.environ['THREAT_INTEL_DB_PATH'] = 'ti_test.sqlite'
os.environ['CERT_CHECK_WEBHOOK_URL'] = 'https://webhook.example/retry-pass'
os.environ['CERT_CHECK_WEBHOOK_SECRET'] = 'secret123'
import sys, pathlib
root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
import importlib
import src.integrations.cert_checks as cc
importlib.reload(cc)
importlib.reload(cc)
print('module db path:', cc.DB_PATH, 'webhook url:', cc._WEBHOOK_URL)
calls = {'post': []}

def fake_get(url, timeout=5.0):
    return type('R', (), {'status_code': 200, 'headers': {'content-type': 'application/json'}, 'json': lambda self: {}})()

def fake_post(url, data=None, headers=None, timeout=5.0):
    print('fake_post called', url)
    calls['post'].append({'url': url, 'data': data, 'headers': headers})
    return type('R', (), {'status_code': 200, 'json': lambda self: {}})()

cc.httpx = types.SimpleNamespace(get=fake_get, post=fake_post)
payload = json.dumps({'findings': [{'certfp': 'flag-cert-999', 'status': 'suspicious', 'details': 'x', 'ts': int(time.time())}], 'count': 1})
cc._persist_failed_batch(payload, 1, 'simulated')
print('persisted, calling flush...')
cc.flush_now()
print('calls:', calls)

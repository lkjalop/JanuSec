import importlib, os, json
# set env like test module top
os.environ['API_KEYS_JSON'] = json.dumps([{'key': 'k3', 'scopes': ['factors.search', 'recalibrator.admin']}])
mod = importlib.import_module('tests.test_auto_accept_and_repo')
print('module imported, client exists?', hasattr(mod, 'client'))
resp = mod.client.post('/api/v1/risk/calibration/auto_accept', headers={'x-api-key':'k3'})
print('status', resp.status_code)
print(resp.text)

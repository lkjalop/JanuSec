import os
import sys
import tempfile
import importlib
import json
import traceback

sys.path.insert(0, os.getcwd())
print('cwd:', os.getcwd())
print('tempdir:', tempfile.gettempdir())

p = os.path.join(tempfile.gettempdir(), 'connectors_secrets_test.json')
if os.path.exists(p):
    try:
        os.remove(p)
        print('removed existing file')
    except Exception as e:
        print('remove failed', e)

os.environ['CONNECTORS_SECRETS_PATH'] = p
print('env CONNECTORS_SECRETS_PATH =', os.environ['CONNECTORS_SECRETS_PATH'])

mod = importlib.import_module('src.api.connector_admin_endpoints')
print('module _SECRETS_PATH:', getattr(mod, '_SECRETS_PATH'))

try:
    mod._save_secrets({'purview': {'api_key': 'abc', 'tenant': 't1'}})
    print('save called')
    print('exists?', os.path.exists(p))
    if os.path.exists(p):
        with open(p, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print('file size:', os.path.getsize(p))
        print('keys:', list(data.keys()))
except Exception as e:
    print('exception:', repr(e))
    traceback.print_exc()

print('done')

import os, json, importlib, sys
from fastapi.testclient import TestClient
# ensure project root on path for direct script runs
sys.path.insert(0, '.')
os.environ['API_KEYS_JSON']='[{"key":"key-no-scope","scopes":[]},{"key":"key-feedback","scopes":["feedback.write"]}]'
# mimic pytest environment
os.environ['PYTEST_CURRENT_TEST']='1'
# import app
from src.api.app import app
client = TestClient(app)
# ensure decision present
from src.api import runtime_state as _rs
_rs.cache_set('evt-x', {'event_id':'evt-x','verdict':'OBSERVE','confidence':0.1,'factors':[]})
# make requests
r1 = client.post('/api/v1/decisions/evt-x/label', json={'label':'tp'})
print('no auth:', r1.status_code)
r2 = client.post('/api/v1/decisions/evt-x/label', headers={'x-api-key':'key-no-scope'}, json={'label':'tp'})
print('no scope key:', r2.status_code, r2.text)
r3 = client.post('/api/v1/decisions/evt-x/label', headers={'x-api-key':'key-feedback'}, json={'label':'tp'})
print('feedback key:', r3.status_code, r3.text)
# introspect auth module
import src.security.auth as sa
importlib.reload(sa)
print('API_KEYS_RAW:', sa._API_KEYS_RAW)
print('API_KEYS:', sa._load_api_keys())
print('match feedback.write:', sa._match_scopes(sa._load_api_keys().get('key-feedback',[]), ['feedback.write']))
print('require_scopes for feedback.write fn:', sa.require_scopes('feedback.write'))

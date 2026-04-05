import os
os.environ.setdefault('PYTEST_CURRENT_TEST','1')
os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('FAST_TEST_MODE','1')
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
os.environ.setdefault('DEBUG_DIAGNOSTICS','1')
# Import test conftest to install its shims
import importlib
importlib.import_module('tests.conftest')
from fastapi.testclient import TestClient
from src.api.app import app
from src.api.runtime_state import get_server_runtime_state, get_file_batch_analysis
client = TestClient(app)
runtime = get_server_runtime_state(app)
fb = get_file_batch_analysis(runtime)
fb.clear()
fb['batch-A'] = {'files': [{'sha256': 'aaa1', 'factors': ['high_entropy']}]}
r1 = client.post('/api/v1/graph/session/build', json={'session_ids': ['batch-A'], 'correlate': True, 'ewma': False})
print('status', r1.status_code)
print('text', r1.text[:500])
if r1.status_code != 200:
    de = client.get('/api/v1/debug/last-errors')
    print('debug', de.json())

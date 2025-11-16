import sys, types
# lightweight stub for psycopg2 often missing in constrained test environments
if 'psycopg2' not in sys.modules:
    sys.modules['psycopg2'] = types.ModuleType('psycopg2')
    for sub in ('extras','extensions','pool'):
        sys.modules.setdefault(f'psycopg2.{sub}', types.ModuleType(f'psycopg2.{sub}'))
from fastapi.testclient import TestClient
from src.api.app import app
import json, time
print('Starting smoke client')
client = TestClient(app)
# Build a simple session payload matching BuildSessionRequest
payload = {
    # Use synthetic deterministic test batches that the server will synthesize when missing
    'session_ids': ['batch-overlap-1', 'batch-overlap-2'],
    'correlate': True,
    'ewma': True,
    'ewma_alpha': 0.6,
    # optional test hints accepted by server when TEST_HELPERS_ENABLED
    'test_ips': ['8.8.8.8', '10.0.0.5']
}

r = client.post('/api/v1/graph/session/build', json=payload)
print('graph build status', r.status_code)
print('graph build headers:', dict(r.headers))
try:
    j = r.json()
    print('graph build full json:', json.dumps(j, indent=2)[:2000])
    print('graph build keys:', list(j.keys()))
except Exception:
    print('graph build no json, text:', r.text[:2000])
# now request report generation (real app exposes /api/v1/report/generate)
report_payload = {'summary': j.get('summary') if isinstance(j, dict) else {}, 'rows': [], 'meta': {'source': 'smoke'}}
r2 = client.post('/api/v1/report/generate?format=html&include_model=true&include_scenarios=true', json=report_payload)
print('report status', r2.status_code)
try:
    print('report len', len(r2.text))
except Exception:
    print('report no text')
print('Done')
import sys, types
# lightweight stub for psycopg2 often missing in constrained test environments
if 'psycopg2' not in sys.modules:
    sys.modules['psycopg2'] = types.ModuleType('psycopg2')
    for sub in ('extras','extensions','pool'):
        sys.modules.setdefault(f'psycopg2.{sub}', types.ModuleType(f'psycopg2.{sub}'))
from fastapi.testclient import TestClient
from src.api.app import app
import json, time
print('Starting smoke client')
client = TestClient(app)
# Build a simple session from inline rows
r = client.post('/api/v1/graph/session/build', json=payload)
print('graph build status', r.status_code)
try:
    j = r.json()
    print('graph build summary keys', list(j.get('summary',{}).keys()))
except Exception:
    print('graph build no json', r.text[:200])
# now request report generation (real app exposes /api/v1/report/generate)
report_payload = {'summary': j.get('summary') if isinstance(j, dict) else {}, 'rows': [], 'meta': {'source': 'smoke'}}
r2 = client.post('/api/v1/report/generate?format=html&include_model=true&include_scenarios=true', json=report_payload)
print('report status', r2.status_code)
try:
    print('report len', len(r2.text))
except Exception:
    print('report no text')
print('Done')

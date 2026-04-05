from fastapi.testclient import TestClient
from src.api.app import app
import time
client = TestClient(app)
rows = [
    {'row_index': 1, 'triage_score': 0.8, 'status': 'new', '_pipeline_done': False, 'factors': ['x','y'], 'ingested_ts': time.time() - 3600},
    {'row_index': 2, 'triage_score': 0.2, 'status': 'ready', '_pipeline_done': True, 'factors': ['z'], 'ingested_ts': time.time() - 100000},
    {'row_index': 3, 'triage_score': 0.6, 'status': 'pending', '_pipeline_done': False, 'factors': ['x'], 'ingested_ts': time.time() - 50000},
]
r = client.post('/api/v1/forward/backlog_report', json={'rows': rows})
print('status', r.status_code)
try:
    print(r.text)
    print(r.json())
except Exception as e:
    print('no json', e)

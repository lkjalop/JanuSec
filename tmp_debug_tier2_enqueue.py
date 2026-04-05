import traceback
from fastapi.testclient import TestClient
from src.api.app import create_app

app = create_app({'mode':'test'})
client = TestClient(app)
rows = [{'row_index': 0, 'raw': {'process_name': 'cmd.exe', 'host': 'host1', 'verdict': 'suspicious'}}]
try:
    resp = client.post('/api/v1/insights/tier2/enqueue', json={'rows': rows})
    print('STATUS', resp.status_code)
    try:
        print('BODY', resp.json())
    except Exception:
        print('TEXT', resp.text)
except Exception as e:
    print('EXC')
    traceback.print_exc()

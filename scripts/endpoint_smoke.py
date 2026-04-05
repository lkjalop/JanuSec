import sys, os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from src.api.app import app
from fastapi.testclient import TestClient

c = TestClient(app)

print('GET /api/v1/admin/risk_profiles')
r = c.get('/api/v1/admin/risk_profiles')
print(r.status_code, r.json())

print('\nGET /api/v1/reports/attention')
r = c.get('/api/v1/reports/attention')
print(r.status_code, r.json())

# create a fake snapshot file to send
import json, os
os.makedirs('reports/snapshots', exist_ok=True)
report = {'report_id': 'smoke-1', 'verdict': {'final_verdict': 'MALWARE', 'final_confidence': 0.87}, 'rows': [], 'summary': {'title':'smoke'}, 'risk_quantification': {'severity':'HIGH','expected_loss_usd':10000}}
with open('reports/snapshots/smoke-1.json','w',encoding='utf-8') as f:
    json.dump({'payload': report}, f)

print('\nPOST /api/v1/reports/smoke-1/send (no recipients)')
r = c.post('/api/v1/reports/smoke-1/send', json={'recipients': []})
print(r.status_code, r.json())

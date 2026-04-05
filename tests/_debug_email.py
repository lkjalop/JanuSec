import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fastapi.testclient import TestClient
import src.api.app as appmod


class MockHG:
    def add_edge(self, *a, **k):
        pass
    def add_node_attr(self, *a, **k):
        pass


client = TestClient(appmod.app)
appmod.app.GLOBAL_HOPGRAPH = MockHG()
payload = {
    'from': 'ceo@paypa¶2.com',
    'to': 'finance@example.com',
    'subject': 'Urgent wire transfer needed',
    'raw': {'body': 'Please complete payment: https://bit.ly/xyz'}
}
r = client.post('/api/v1/email/ingest', json=payload)
print('status', r.status_code)
try:
    print('json:', r.json())
except Exception:
    print('text:', r.text)

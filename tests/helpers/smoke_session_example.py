# Helper demonstrating deterministic /api/v1/graph/session/build use
# Use in local dev with TEST_HELPERS_ENABLED=1
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)

def build_demo_session():
    payload = {
        'session_ids': ['batch-overlap-1','batch-overlap-2'],
        'correlate': True,
        'ewma': True,
        'ewma_alpha': 0.6
    }
    r = client.post('/api/v1/graph/session/build', json=payload)
    return r

if __name__ == '__main__':
    r = build_demo_session()
    print(r.status_code)
    try:
        print(r.json())
    except Exception:
        print(r.text)

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
        'ewma_alpha': 0.6,
        # Provide an explicit mapping so backend-generated mapping stats / entity
        # resolution outputs can be validated end-to-end from the helper run.
        'mapping': {
            'user': 'username',
            'host': 'hostname',
            'ip_src': 'src_ip',
            'ip_dst': 'dest_ip',
            'process': 'process_name',
            'file_hash': 'sha256',
            'domain': 'domain_name'
        },
        # Provide explicit helper entity values so entity resolution previews can be validated.
        'helper_entities': {
            'batch-overlap-1': {
                'user': ['alfa.ops'],
                'host': ['ws-4477'],
                'ip_src': ['10.70.5.14', '192.168.1.99'],
                'ip_dst': ['8.8.8.8'],
            },
            'batch-overlap-2': {
                'user': ['alfa.ops'],
                'host': ['ws-4477'],
                'ip_src': ['10.70.5.14'],
                'ip_dst': ['8.8.4.4'],
                'domain': ['lab.infra.example'],
            },
        },
    }
    headers = {'X-Roles': 'analyst'}
    r = client.post('/api/v1/graph/session/build', json=payload, headers=headers)
    return r

if __name__ == '__main__':
    r = build_demo_session()
    print(r.status_code)
    try:
        print(r.json())
    except Exception:
        print(r.text)

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from src.api.app import app


def main():
    client = TestClient(app)
    r = client.get('/api/v1/graph/self_check')
    out = r.json() if r.status_code == 200 else {'error': 'not_found', 'status': r.status_code}
    path = 'self_check_output.json'
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(out, fh, indent=2)
    print('Wrote', path)

if __name__ == '__main__':
    main()

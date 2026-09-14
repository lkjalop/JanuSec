import traceback
from fastapi import FastAPI
from fastapi.testclient import TestClient
import inspect
import sys
from pathlib import Path

# Ensure project root is on sys.path so `src` imports work when running this script
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def main():
    from src.api.ebpf_endpoints import ingest_ebpf_event

    app = FastAPI()
    app.post('/api/v1/events/ebpf_ingest')(ingest_ebpf_event)

    print('Registered routes:')
    for r in app.router.routes:
        try:
            ep = getattr(r, 'endpoint', None)
            name = ep.__name__ if ep is not None else str(r)
        except Exception:
            name = str(r)
        print('-', r.path, 'methods=', getattr(r, 'methods', None), 'name=', name)

    client = TestClient(app)
    print('\nSending POST to /api/v1/events/ebpf_ingest')
    r = client.post('/api/v1/events/ebpf_ingest', json={'output':'x'})
    print('Status:', r.status_code)
    print('Response body:', r.text)

    print('\nHandler callable and signature:')
    print(ingest_ebpf_event)
    print(inspect.signature(ingest_ebpf_event))

if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Exception during debug:')
        traceback.print_exc()

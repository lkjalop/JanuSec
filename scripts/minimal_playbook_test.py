import sys
from pathlib import Path
p = Path(__file__).resolve().parents[1]
if str(p) not in sys.path:
    sys.path.insert(0, str(p))
from fastapi import FastAPI, Request, Depends
from fastapi.testclient import TestClient

try:
    from src.security.auth import auth_dependency
except Exception as e:
    auth_dependency = lambda *a, **k: None

app = FastAPI()

async def handler(request: Request, auth = Depends(auth_dependency)):
    b = await request.json()
    return {'ok': True, 'body': b}

app.post('/test')(handler)

if __name__ == '__main__':
    client = TestClient(app)
    headers = {'x-api-key': 'testkey123'}
    resp = client.post('/test', json={'action':'restart_collector','target':'demo_collector'}, headers=headers)
    print('status', resp.status_code)
    try:
        print('json:', resp.json())
    except Exception:
        print('text:', resp.text)

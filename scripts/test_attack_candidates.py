import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api import graph_session_endpoints as g

app = FastAPI()
app.include_router(g.router)
client = TestClient(app)

# Create two inline sessions with overlapping entities
s1 = {'id':'s1','entities':{'user':'alice','host':'host-a','process':'notepad.exe','sha256':'aaaabbbbcccc11112222'}}
s2 = {'id':'s2','entities':{'user':'alice','host':'host-b','process':'cmd.exe','domain':'malicious.example','sha256':'aaaabbbbcccc11112222'}}

payload = {'sessions':[s1,s2], 'correlate': True, 'ewma': False}

r = client.post('/api/v1/graph/attack_candidates', json=payload)
print('Status', r.status_code)
print(r.json())

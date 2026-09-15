import os
import sys
import json
from pathlib import Path
from fastapi import FastAPI
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ['LLM_MOCK'] = '1'
from src.api import tier2_endpoints as t2

app = FastAPI()
app.include_router(t2.router)
client = TestClient(app)

payload = {
    'assessment_id': 'A1',
    'rows': [
        {'row_index': 1, 'summary': 'dns qname malicious.example.com', 'type': 'dns', 'qname': 'malicious.example.com'},
    ],
}

resp = client.post('/api/v1/csv/tier2_sse', json=payload)
print('status', resp.status_code)
print(resp.text[:1000])

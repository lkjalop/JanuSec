import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI
from fastapi.testclient import TestClient

# Import only our suggestions router directly to avoid heavy app imports
from src.api import suggestions_endpoints as suggestions

app = FastAPI()
app.include_router(suggestions.router)
client = TestClient(app)

payload = {
    "row": {
        "ts": 1700000000,
        "user": "victim",
        "process_name": "suspicious.exe",
        "path": "C:\\Users\\victim\\AppData\\Local\\suspicious.exe",
        "cmdline": "--do-evil",
        "sha256": "deadbeefcafebabe",
    },
    "human_assessment": {
        "assessor": "alice",
        "comment": "suspicious",
        "tags": ["suspicious","malicious"],
        "playbook_ref": "PB-123"
    }
}

r = client.post('/api/v1/suggestions/provenance', json=payload)
print('POST status:', r.status_code)
print('POST body:', r.json())

r2 = client.get('/api/v1/suggestions/provenance', params={'filter':'assessed','page':1,'limit':10})
print('GET status:', r2.status_code)
print('GET body:', r2.json())

from pathlib import Path
import sys
from fastapi import FastAPI
from fastapi.testclient import TestClient
import importlib

# Ensure project root is importable
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    crq = importlib.import_module('src.api.crq_observations_endpoints')
    jobs = importlib.import_module('src.api.admin_enrichment_scheduler')
except Exception as e:
    print('Import error:', e)
    raise

app = FastAPI()
app.include_router(crq.router)
app.include_router(jobs.router)

client = TestClient(app)

print('CRQ endpoint status:', client.get('/api/v1/crq/recent').status_code)
resp = client.get('/api/v1/admin/enrichment/jobs')
print('Jobs endpoint status:', resp.status_code)
try:
    print('Jobs JSON:', resp.json())
except Exception as e:
    print('Jobs JSON error:', e)

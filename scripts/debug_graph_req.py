import sys
from pathlib import Path
# Ensure repo root is on sys.path so local imports resolve like pytest
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SRC = ROOT / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from fastapi.testclient import TestClient
import src.api.server as server_mod

client = TestClient(server_mod.app)
resp = client.post('/api/v1/graph/reconstruct?attach_incident=true', json={'user':'z'}, headers={'x-api-key':'devkey123'})
print('STATUS:', resp.status_code)
try:
    j = resp.json()
    print('JSON:', j)
except Exception:
    print('TEXT:', resp.text[:2000])

# If an exception was raised server-side, TestClient includes the traceback in .text
# Print a short slice to aid debugging
print('\n--- FULL RESPONSE TEXT (first 4000 chars) ---')
print(resp.text[:4000])

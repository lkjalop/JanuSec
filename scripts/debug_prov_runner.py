import sys
import time
from pathlib import Path
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))

from fastapi.testclient import TestClient
from src.api.server import app
from src.api import runtime_state
from src.api.dependencies import get_platform_state

client = TestClient(app)

ev = {
    'id': 'prov-evt-debug',
    'host': 'host-prov',
    'details': {'process': {'name': 'powershell.exe', 'parent': 'explorer.exe'}},
    'powershell_encoded': True,
    'amsi_disable_call': True,
}

print('posting')
r = client.post('/api/v1/events', json=ev)
print('status', r.status_code, r.text)
if r.status_code == 200:
    eid = r.json().get('event_id')
    time.sleep(0.5)
    cache = getattr(runtime_state, 'DECISION_CACHE', None)
    print('DECISION_CACHE dict?', isinstance(cache, dict))
    if isinstance(cache, dict):
        dec = cache.get(eid)
        print('cache entry type:', type(dec))
        try:
            print('cache entry dump:', getattr(dec, 'model_dump', lambda: dec)())
        except Exception as e:
            print('dump failed', e)
    ps = get_platform_state()
    try:
        dec2 = ps._decisions.get(eid)
        print('platformstate entry type:', type(dec2))
        try:
            print('platformstate dump:', getattr(dec2, 'model_dump', lambda: dec2)())
        except Exception as e:
            print('ps dump failed', e)
    except Exception as e:
        print('ps lookup failed', e)

from fastapi.testclient import TestClient
from src.api.app import create_app
from src.live import asn_lookup, asn_stats
from src.api import runtime_state
import os
app = create_app()
client = TestClient(app)
asn_lookup.clear_mapping()
asn_lookup.seed_mapping({'8.8.8.8':'AS65001','8.8.4.4':'AS65002'})
runtime_state.reset_for_tests()
os.environ['ASN_RARITY_THRESHOLD']='0.0'
payload={"session_ids":["batch-overlap-A","batch-overlap-B"],"correlate":True,"ewma":False}
resp=client.post('/api/v1/graph/session/build', json=payload)
print('STATUS',resp.status_code)
try:
    print('JSON',resp.json())
except Exception:
    print('TEXT',resp.text)

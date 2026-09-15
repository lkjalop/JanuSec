import os, json, time
from fastapi.testclient import TestClient
from src.api.app import create_app
from src.live import asn_lookup, asn_stats
from src.api.runtime_state import reset_for_tests as runtime_reset
from src.incidents.aggregator import GLOBAL_INCIDENTS
from src.api import graph_sessions

# Ensure test helpers env
os.environ['TEST_HELPERS_ENABLED'] = '1'
os.environ['INCIDENT_AUTOGEN_ENABLED'] = '1'
os.environ['INCIDENT_AUTOGEN_PATH_THRESHOLD'] = '0.8'

app = create_app()
client = TestClient(app)

# Seed ASN mapping used in tests
asn_lookup.clear_mapping()
asn_lookup.seed_mapping({'8.8.8.8': 'AS65001', '8.8.4.4': 'AS65002'})
runtime_reset()

payload = {
    "session_ids": ["batch-overlap-A","batch-overlap-B"],
    "correlate": True,
    "ewma": False,
    "test_discoveries": [
        {"type": "path", "signals": ["b1__b2"], "confidence": 0.95, "rationale": ["test-high-confidence"], "session_id": '__USE_CURRENT__'}
    ]
}

r = client.post('/api/v1/graph/session/build', json=payload)
print('status', r.status_code)
try:
    j = r.json()
    print(json.dumps(j, indent=2)[:4000])
except Exception as e:
    print('json_err', e, r.text[:2000])

print('GLOBAL_INCIDENTS count:', len(GLOBAL_INCIDENTS.list_incidents()))
print('ASN percentile AS65001:', asn_stats.percentile('AS65001'))
print('ASN rarity AS65001:', asn_stats.rarity('AS65001'))
print('ASN store sample:', dict(list(asn_stats._counts.items())[:10]) if hasattr(asn_stats,'_counts') else 'no_counts')

print('DISCOVERIES snapshot:')
for k,d in list(graph_sessions._DISCOVERIES.items())[:10]:
    print(k, d)

# show path discoveries for the created session
sid = j.get('summary',{}).get('session_id') if isinstance(j, dict) else None
print('session_id', sid)
if sid:
    pds = [d for d in graph_sessions._DISCOVERIES.values() if d.get('session_id')==sid and d.get('type')=='path']
    print('path discoveries for session:', pds)

print('done')

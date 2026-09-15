from fastapi.testclient import TestClient
from api.server import app, DECISION_CACHE, _record_decision
from api import report_aggregation
import json

client = TestClient(app)

DECISION_CACHE.clear()
_record_decision('evt-scn-1', 'SUSPICIOUS', 0.6, ['dns:tunnel_suspected','net:beacon_periodic','ssl:ja3_rare'])
_record_decision('evt-scn-2', 'SUSPICIOUS', 0.6, ['endpoint:lolbin_certutil_suspicious','endpoint:persistence_candidate'])

r = client.get('/api/v1/report/ingestion?include_scenarios=true&include_model=true')
print('status', r.status_code)
try:
    data = r.json()
    print(json.dumps(data, indent=2))
except Exception as e:
    print('json error', e)

print('\nDECISION_CACHE entries:')
for k,v in list(DECISION_CACHE.items()):
    print(k, type(v), getattr(v,'event_id', None), getattr(v,'verdict', None), v.get('factors') if isinstance(v, dict) else getattr(v,'factors', None))
print('\nDECISION_CACHE id in server:', id(DECISION_CACHE))
print("DECISION_CACHE id as seen by report_aggregation:", id(report_aggregation.DECISION_CACHE))

from fastapi.testclient import TestClient
import json
import src.api.app as appmod
from src.graph.hopgraph import HopGraph

hg = HopGraph()
appmod.app.GLOBAL_HOPGRAPH = hg
client = TestClient(appmod.app)
with open('tests/fixtures/e2e_multi_stage_attack.json', 'r', encoding='utf-8') as fh:
    data = json.load(fh)

for ev in data['events']:
    t = ev.get('type')
    p = ev.get('payload') or {}
    if t == 'email':
        r = client.post('/api/v1/email/ingest', json=p)
    elif t == 'remote_access':
        r = client.post('/api/v1/remote_access/ingest', json=p)
    elif t == 'endpoint':
        evt = {
            'host': p.get('host'),
            'process': {
                'name': p.get('process'),
                'command': p.get('command')
            },
            'details': {'user': p.get('user')}
        }
        r = client.post('/api/v1/endpoints/log_batch', json={'events': [evt]})
    elif t == 'data_access':
        r = client.post('/api/v1/data/ingest', json=p)
    else:
        r = None
    print('POST', t, '->', getattr(r, 'status_code', None))

print('HopGraph nodes:')
for k in sorted(hg.nodes.keys()):
    print(k)

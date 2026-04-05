from fastapi.testclient import TestClient
import src.api.app as appmod
from src.graph.hopgraph import HopGraph
import json
hg = HopGraph()
appmod.app.GLOBAL_HOPGRAPH = hg
client = TestClient(appmod.app)
with open('tests/fixtures/e2e_multi_stage_attack.json','r',encoding='utf-8') as fh:
    data = json.load(fh)
for ev in data['events']:
    t = ev['type']
    p = ev['payload']
    if t == 'email':
        r = client.post('/api/v1/email/ingest', json=p)
    elif t == 'remote_access':
        r = client.post('/api/v1/remote_access/ingest', json=p)
    elif t == 'endpoint':
        evt = {'host':p['host'],'process':{'name':p['process'],'command':p['command']},'details':{'user':p['user']}}
        r = client.post('/api/v1/endpoints/log_batch', json={'events':[evt]})
    elif t == 'data_access':
        r = client.post('/api/v1/data/ingest', json=p)
    print(t, r.status_code)
print('nodes', list(hg.nodes.keys()))

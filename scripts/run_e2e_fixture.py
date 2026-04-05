import os, sys, json
sys.path.insert(0, os.getcwd())
from fastapi.testclient import TestClient
import src.api.app as appmod
from src.graph.hopgraph import HopGraph
hg = HopGraph()
appmod.app.GLOBAL_HOPGRAPH = hg
client = TestClient(appmod.app)
data = json.load(open('tests/fixtures/e2e_multi_stage_attack.json'))
for ev in data['events']:
    t = ev.get('type')
    p = ev.get('payload') or {}
    if t=='email':
        r = client.post('/api/v1/email/ingest', json=p)
        print('email', r.status_code, r.json())
    elif t=='remote_access':
        r = client.post('/api/v1/remote_access/ingest', json=p)
        print('ra', r.status_code, r.json())
    elif t=='endpoint':
        evt = {'host': p.get('host'), 'process': {'name': p.get('process'), 'command': p.get('command')}, 'details': {'user': p.get('user')}}
        r = client.post('/api/v1/endpoints/log_batch', json={'events':[evt]})
        print('endpoint', r.status_code)
    elif t=='data_access':
        r = client.post('/api/v1/data/ingest', json=p)
        print('data', r.status_code, r.json())
print('nodes keys:', list(hg.nodes.keys()))
print('adj keys:', list(hg.adj.keys()))
for src, lst in hg.adj.items():
    print(src, '->', lst)

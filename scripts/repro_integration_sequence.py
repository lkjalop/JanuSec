import os, json, time, sys
sys.path.append('.')
os.environ['TEST_HELPERS_ENABLED'] = '1'

from src.enrichment import consumer as _consumer

# write seed
os.makedirs('data', exist_ok=True)
with open('data/crq_shadow.json','w',encoding='utf-8') as fh:
    json.dump([{'hash':'ff'*16,'expected_loss':2000.0,'dread_inputs':{'damage':1,'exploitability':1},'meta':{}}], fh)

# Attempt to import GLOBAL_HOPGRAPH like test
called = {'args': []}
try:
    from src.graph.hopgraph import GLOBAL_HOPGRAPH as GH
except Exception:
    try:
        from src.core.graph.hopgraph_core import GLOBAL_HOPGRAPH as GH
    except Exception:
        GH = None

if GH is not None:
    def _fake_ingest(ev, source=None):
        called['args'].append((ev, source))
        return True
    # monkeypatch by assigning attribute on the object (like test doing monkeypatch.setattr)
    try:
        GH.ingest_event = _fake_ingest
    except Exception:
        pass

# Now override module GLOBAL_HOPGRAPH with DummyHopGraph
class DummyHopGraph:
    def __init__(self):
        self.events = []
    def ingest_event(self, ev, source=None):
        print('DummyHopGraph.ingest_event called', ev, source)
        self.events.append((ev, source))
        return True

try:
    import src.graph.hopgraph as _hgmod
    _hgmod.GLOBAL_HOPGRAPH = DummyHopGraph()
except Exception:
    try:
        import src.core.graph.hopgraph_core as _hgmod2
        _hgmod2.GLOBAL_HOPGRAPH = DummyHopGraph()
    except Exception:
        pass

ev = {'type': 'enrichment:epss_high', 'hash': 'bb'*16, 'score': 0.9, 'ts': time.time(), 'meta': {'tenant': 'tenantA', 'host': 'host1'}}

def fake_compute(row):
    return {'expected_loss': 2000.0, 'dread_inputs': {'damage': 1, 'exploitability': 1}}

_consumer.compute_fair_row = fake_compute

def fake_persist(obs):
    print('persist called', obs)
    arr=[]
    p='data/crq_shadow.json'
    try:
        arr=json.loads(open(p,'r',encoding='utf-8').read() or '[]')
    except Exception:
        arr=[]
    arr.append(obs)
    open(p,'w',encoding='utf-8').write(json.dumps(arr))

_consumer.persist_shadow_observation = fake_persist

import asyncio
asyncio.run(_consumer._process_event(ev))

print('called list:', called)

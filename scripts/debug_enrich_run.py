import os
import time
import json

class DummyHopGraph:
    def __init__(self):
        self.events = []
    def ingest_event(self, ev, source=None):
        print('DummyHopGraph.ingest_event called', ev, source)
        self.events.append((ev, source))
        return True

def dummy_compute_fair_row(row):
    return {'expected_loss': 2000.0, 'dread_inputs': {'damage': 1, 'exploitability': 1}}

os.environ['TEST_HELPERS_ENABLED'] = '1'

try:
    # attach dummy hopgraph
    import src.graph.hopgraph as _hgmod
    _hgmod.GLOBAL_HOPGRAPH = DummyHopGraph()
except Exception:
    try:
        import src.core.graph.hopgraph_core as _hgmod2
        _hgmod2.GLOBAL_HOPGRAPH = DummyHopGraph()
    except Exception:
        pass

ev = {'type': 'enrichment:epss_high', 'hash': 'bb'*16, 'score': 0.9, 'ts': time.time(), 'meta': {'tenant': 'tenantA', 'host': 'host1'}}

from src.enrichment import consumer as _consumer

_consumer.compute_fair_row = dummy_compute_fair_row

def _fake_persist(obs):
    print('persist called with obs:', obs)
    # also write to file
    p = os.path.join('data','crq_shadow.json')
    arr = []
    if os.path.exists(p):
        try:
            arr = json.loads(open(p,'r',encoding='utf-8').read() or '[]')
        except Exception:
            arr = []
    arr.append(obs)
    open(p,'w',encoding='utf-8').write(json.dumps(arr))

_consumer.persist_shadow_observation = _fake_persist

import asyncio
asyncio.run(_consumer._process_event(ev))

print('done')

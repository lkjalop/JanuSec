import os, sys, time, json
sys.path.append('.')
os.environ['TEST_DEBUG'] = '1'

from src.enrichment import consumer as _consumer
from src.crq import fair_shadow as _fs

def _fake_compute(row):
    return {'expected_loss': 2000.0, 'dread_inputs': {'damage': 1, 'exploitability': 1}}

_consumer.compute_fair_row = _fake_compute
_consumer.persist_shadow_observation = getattr(_fs, 'persist_shadow_observation', None)

ev = {'type': 'enrichment:epss_high', 'hash': 'bb'*16, 'score': 0.9, 'ts': time.time(), 'meta': {'tenant': 'tenantA', 'host': 'host1'}}

import asyncio
asyncio.run(_consumer._process_event(ev))

print('CRQ file contents:')
try:
    print(open('data/crq_shadow.json','r',encoding='utf-8').read())
except Exception as e:
    print('read error', e)

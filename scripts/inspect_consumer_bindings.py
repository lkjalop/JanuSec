import os, time, sys, json
sys.path.append('.')
os.environ['TEST_HELPERS_ENABLED'] = '1'

from src.api.runtime_state import EVENT_QUEUE

from src.crq import fair_shadow as _fs
from src.enrichment import consumer as _consumer

print('Before assigning, module has compute:', getattr(_consumer, 'compute_fair_row', None), 'persist:', getattr(_consumer, 'persist_shadow_observation', None))

# Simulate test monkeypatch behavior
def _fake_compute(row):
    return {'expected_loss': 2000.0, 'dread_inputs': {'damage': 1, 'exploitability': 1}}

_consumer.compute_fair_row = _fake_compute
_consumer.persist_shadow_observation = getattr(_fs, 'persist_shadow_observation', None)

print('After assigning, module has compute:', getattr(_consumer, 'compute_fair_row', None), 'persist:', getattr(_consumer, 'persist_shadow_observation', None))

ev = {'type': 'enrichment:epss_high', 'hash': 'bb'*16, 'score': 0.9, 'ts': time.time(), 'meta': {'tenant': 'tenantA', 'host': 'host1'}}

import asyncio
asyncio.run(_consumer._process_event(ev))

print('PERSIST FILE CONTENTS:')
try:
    with open('data/crq_shadow.json','r',encoding='utf-8') as fh:
        print(fh.read())
except Exception as e:
    print('read error', e)

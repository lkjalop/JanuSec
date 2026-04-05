import asyncio
import importlib
import os
import sys
sys.path.insert(0, os.getcwd())

# Reproduce the test's monkeypatching and call _forward_items
mod = importlib.import_module('scripts.redis_streams_consumer')

class FakeRedis:
    def __init__(self):
        self.store = {}
    async def set(self, key, val, ex=None, nx=False):
        print('FakeRedis.set called', key, nx)
        if nx and key in self.store:
            return False
        self.store[key] = val
        return True

class FakeResp:
    def __init__(self):
        self.status_code = 200

class FakeHttp:
    def __init__(self):
        self.posts = []
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        return False
    async def post(self, url, json=None, headers=None):
        print('FakeHttp.post called', url, json)
        self.posts.append(json)
        return FakeResp()

# Monkeypatch module-level httpx as tests do
mod.httpx = type('M', (), {'AsyncClient': lambda *a, **k: FakeHttp()})

client = FakeRedis()
events = [{'event_id': 'a', 'value': 1}, {'event_id': 'a', 'value': 1}, {'event_id': 'b', 'value': 2}]

print('httpx in module:', mod.httpx)
print('httpx type:', type(mod.httpx))

async def run():
    ok = await mod._forward_items(client, events)
    print('result:', ok)

if __name__ == '__main__':
    # ensure deterministic test-mode
    os.environ['JANUSEC_TEST_MODE'] = '1'
    asyncio.run(run())

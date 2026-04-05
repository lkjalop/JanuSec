import asyncio
import json
import pytest


@pytest.mark.asyncio
async def test_dedupe_forward(monkeypatch):
    # Prepare fake redis client where set returns True for first id and False for duplicate
    calls = {'set_calls': []}

    class FakeRedis:
        def __init__(self):
            self.store = {}

        async def set(self, key, val, ex=None, nx=False):
            calls['set_calls'].append(key)
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

        async def post(self, url, json=None):
            self.posts.append(json)
            return FakeResp()

    # monkeypatch httpx.AsyncClient used in consumer
    import importlib
    mod = importlib.import_module('scripts.redis_streams_consumer')
    mod.httpx = type('M', (), {'AsyncClient': lambda *a, **k: FakeHttp()})

    client = FakeRedis()
    events = [{'event_id': 'a', 'value': 1}, {'event_id': 'a', 'value': 1}, {'event_id': 'b', 'value': 2}]
    ok = await mod._forward_items(client, events)
    assert ok is True
    # Expect set called for each event; second for 'a' should return False and not be forwarded
    assert len(calls['set_calls']) >= 3

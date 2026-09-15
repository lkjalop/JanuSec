import asyncio
import json
import pytest


@pytest.mark.asyncio
async def test_drain_and_forward_monkeypatch(monkeypatch):
    # Simulate aioredis client responses and httpx post
    messages = [
        (b'1680000000000-0', {b'data': json.dumps({'events': [{'id': '1'}]})}),
        (b'1680000000001-0', {b'data': json.dumps({'events': [{'id': '2'}]})}),
    ]

    class FakeRedis:
        def __init__(self):
            self.xacks = []

        async def xread_group(self, group, consumer, streams, count, block):
            return [(b'ingest_stream', messages)]

        async def xack(self, stream, group, mid):
            self.xacks.append(mid)

    class FakeResp:
        def __init__(self):
            self.status_code = 200

    # prepare module-level mocks
    monkeypatch.setitem(__import__('sys').modules, 'aioredis', type('M', (), {'from_url': lambda url: FakeRedis()}))
    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json=None):
            return FakeResp()

    monkeypatch.setitem(__import__('sys').modules, 'httpx', type('M', (), {'AsyncClient': lambda *a, **k: FakeClient()}))

    # Import and run one iteration of consumer loop by calling the underlying coroutine directly
    import importlib
    mod = importlib.import_module('scripts.redis_streams_consumer')

    # Patch aioredis.from_url to return our FakeRedis instance
    async def fake_from_url(url):
        return FakeRedis()

    mod.aioredis = type('M', (), {'from_url': fake_from_url})
    mod.httpx = type('M', (), {'AsyncClient': lambda *a, **k: FakeClient()})

    # Run loop but stop after first batch by raising KeyboardInterrupt via monkeypatching xread_group
    async def one_iter():
        client = await mod.aioredis.from_url('redis://localhost')
        # emulate read_group then empty
        called = {'n': 0}

        async def xread_group(group, consumer, streams, count, block):
            if called['n'] == 0:
                called['n'] += 1
                return [(b'ingest_stream', messages)]
            else:
                await asyncio.sleep(0.01)
                return []

        client.xread_group = xread_group

        async def xack(s, g, mid):
            return await asyncio.sleep(0)

        client.xack = xack

        async def from_url_override(u):
            return client

        mod.aioredis.from_url = from_url_override

        # run one loop iteration by invoking internal logic: call run but cancel after short delay
        task = asyncio.create_task(mod.run())
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    await one_iter()

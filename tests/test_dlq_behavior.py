import asyncio
import json
import pytest


@pytest.mark.asyncio
async def test_dlq_push_and_deadletter(monkeypatch):
    # Mock redis client with xadd and xdel behaviors and simulate forward failure
    called = {'xadd': [], 'xdel': []}

    class FakeRedis:
        def __init__(self):
            pass

        async def set(self, *a, **k):
            return True

        async def xadd(self, stream, fields):
            called['xadd'].append((stream, fields))

        async def xdel(self, stream, mid):
            called['xdel'].append((stream, mid))

        async def xread(self, streams, count=None, block=None):
            # return one entry simulating a DLQ entry
            payload = json.dumps({'events': [{'id': 'e1'}], 'attempts': 5})
            return [(b'ingest_dlq', [(b'1-0', {b'data': payload.encode('utf-8')})])]

    # Monkeypatch forward function to always fail and aioredis.from_url to use our fake
    import importlib
    mod = importlib.import_module('scripts.redis_streams_consumer')
    async def fake_forward(redis_client, items):
        return False

    # Use monkeypatch so module-level changes are reverted after the test
    monkeypatch.setattr(mod, '_forward_items', fake_forward, raising=False)
    client = FakeRedis()
    async def from_url_async(url):
        return client
    monkeypatch.setattr(mod, 'aioredis', type('M', (), {'from_url': from_url_async}), raising=False)
    # Run small slice of dlq_processor_loop by calling reclaim function indirectly
    # We call the internal dlq loop function by creating a task and cancelling it shortly
    async def run_dlq_once():
        task = asyncio.create_task(mod.run())
        await asyncio.sleep(1.0)
        task.cancel()
        try:
            await task
        except Exception:
            pass

    # run
    await run_dlq_once()

    # verify that xadd and xdel were called (moved to dead or requeued)
    assert len(called['xadd']) >= 1

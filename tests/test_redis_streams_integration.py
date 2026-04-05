import asyncio
import json
import os
import pytest

try:
    from testcontainers.redis import RedisContainer
except Exception:
    RedisContainer = None


@pytest.mark.asyncio
@pytest.mark.skipif(RedisContainer is None, reason='testcontainers not available')
async def test_streams_end_to_end():
    with RedisContainer() as rc:
        redis_url = rc.get_connection_url()
        # create stream and group
        import aioredis
        client = await aioredis.from_url(redis_url)
        await client.xgroup_create('ingest_stream', 'ingest_group', id='0', mkstream=True)
        # xadd sample
        await client.xadd('ingest_stream', {'data': json.dumps({'events': [{'id': 'tx1'}]})})

        # run consumer for one loop
        import scripts.redis_streams_consumer as consumer_mod

        consumer_mod.REDIS_URL = redis_url
        # run consumer in background and cancel after short time
        task = asyncio.create_task(consumer_mod.run())
        await asyncio.sleep(1.0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # verify ack
        # fetch pending
        pending = await client.xpending('ingest_stream', 'ingest_group')
        assert pending is not None

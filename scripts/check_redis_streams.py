import asyncio
import os
from src.core.redis_streams import RedisStreamsQueue

async def main():
    url = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/0')
    q = RedisStreamsQueue(redis_url=url)
    print('stats before:', q.stats())
    ok = await q.enqueue({'hello': 'world', 'ts': int(__import__('time').time())})
    print('enqueue result:', ok)
    print('stats after:', q.stats())

if __name__ == '__main__':
    asyncio.run(main())

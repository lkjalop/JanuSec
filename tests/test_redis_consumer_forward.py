import asyncio
import json
import pytest

from scripts import redis_streams_consumer as rsc

class FakeRedis:
    def __init__(self):
        self.store = {}
        self.xadd_calls = []
    async def set(self, key, val, ex=None, nx=False):
        if nx and key in self.store:
            return False
        self.store[key] = val
        return True
    async def xadd(self, stream, fields):
        self.xadd_calls.append((stream, fields))
        return 'id'

class FakeHTTP:
    class Resp:
        def __init__(self, status_code):
            self.status_code = status_code
    def __init__(self, status_code=200):
        self.posts = []
        self._status = status_code
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        return False
    async def post(self, url, json=None, headers=None):
        self.posts.append((url, json, headers))
        return FakeHTTP.Resp(self._status)

@pytest.mark.asyncio
async def test_forward_with_fake_redis_and_http(monkeypatch):
    fake_redis = FakeRedis()
    fake_http = FakeHTTP(status_code=200)
    monkeypatch.setattr(rsc, 'httpx', type('M', (), {'AsyncClient': lambda *a, **k: fake_http}))
    events = [{'event_id': 'a', 'value': 1}, {'event_id': 'a', 'value': 1}, {'event_id': 'b', 'value': 2}]
    ok = await rsc._forward_items(fake_redis, events)
    assert ok is True

@pytest.mark.asyncio
async def test_forward_with_real_like_redis_and_non2xx(monkeypatch):
    # real-like redis implements xadd; non-2xx should cause DLQ write and False
    class RealLikeRedis(FakeRedis):
        async def xread_group(self, *a, **k):
            return []
    rl = RealLikeRedis()
    fake_http = FakeHTTP(status_code=500)
    monkeypatch.setattr(rsc, 'httpx', type('M', (), {'AsyncClient': lambda *a, **k: fake_http}))
    events = [{'event_id': 'x', 'value': 99}]
    ok = await rsc._forward_items(rl, events)
    # DLQ write should have been attempted; function returns False for real redis
    assert ok is False
    assert len(rl.xadd_calls) >= 1

import os
import asyncio
import pytest

from scripts import redis_streams_consumer as rsc


class FakeRedis:
    def __init__(self):
        self.store = {}

    async def set(self, key, val, ex=None, nx=False):
        # Simulate set with NX semantics
        if nx and key in self.store:
            return False
        self.store[key] = val
        return True


@pytest.mark.asyncio
async def test_forward_items_respects_test_mode_returns_true(monkeypatch):
    # Ensure explicit test-mode is set
    monkeypatch.setenv('JANUSEC_TEST_MODE', '1')
    fake = FakeRedis()
    items = [{'event_id': 'e1', 'payload': 'x'}, {'event_id': 'e2', 'payload': 'y'}]
    # Call the function under test
    ok = await rsc._forward_items(fake, items)
    assert ok is True


@pytest.mark.asyncio
async def test_forward_items_without_test_mode_makes_http_call(monkeypatch):
    # Ensure test-mode is unset
    monkeypatch.delenv('JANUSEC_TEST_MODE', raising=False)
    fake = FakeRedis()
    # Provide a fake httpx module where AsyncClient.post returns an object with status_code 200
    class Resp:
        status_code = 200

    class FakeAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json=None, headers=None):
            return Resp()

    monkeypatch.setattr(rsc, 'httpx', type('m', (), {'AsyncClient': FakeAsyncClient}))
    items = [{'event_id': 'e3', 'payload': 'z'}]
    ok = await rsc._forward_items(fake, items)
    assert ok is True

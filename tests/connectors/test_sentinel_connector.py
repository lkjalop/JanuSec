from __future__ import annotations

import asyncio

from src.integrations.sentinel_adapter import SentinelAdapter


def test_sentinel_stub_fetch_and_ack():
    conn = SentinelAdapter(tenant='t2')
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(conn.connect())
        events, cursor = loop.run_until_complete(conn.fetch_since(None, limit=5))
        assert events and events[0]['source'] == 'sentinel'
        assert events[0]['tenant'] == 't2'
        if cursor:
            loop.run_until_complete(conn.ack(cursor))
        h = loop.run_until_complete(conn.health())
        assert h['enabled'] is True and h['source'] == 'sentinel'
    finally:
        loop.close()

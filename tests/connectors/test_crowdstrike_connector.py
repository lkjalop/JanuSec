from __future__ import annotations

import asyncio

from src.integrations.crowdstrike_adapter import CrowdStrikeAdapter


def test_crowdstrike_stub_fetch_and_ack():
    conn = CrowdStrikeAdapter(tenant='t1')
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(conn.connect())
        events, cursor = loop.run_until_complete(conn.fetch_since(None, limit=5))
        assert events and events[0]['source'] == 'crowdstrike'
        assert events[0]['tenant'] == 't1'
        if cursor:
            loop.run_until_complete(conn.ack(cursor))
        h = loop.run_until_complete(conn.health())
        assert h['enabled'] is True and h['source'] == 'crowdstrike'
    finally:
        loop.close()

from __future__ import annotations

import asyncio

from src.integrations.splunk_adapter import SplunkAdapter


def test_splunk_stub_fetch_and_ack():
    conn = SplunkAdapter(tenant='test')
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(conn.connect())
        events, cursor = loop.run_until_complete(conn.fetch_since(None, limit=10))
        assert isinstance(events, list) and events
        ev = events[0]
        # canonical fields present
        assert ev.get('source') == 'splunk'
        assert ev.get('tenant') == 'test'
        assert ev.get('event_type') == 'notable'
        # ack cursor and health
        if cursor:
            loop.run_until_complete(conn.ack(cursor))
        h = loop.run_until_complete(conn.health())
        assert h.get('enabled') is True
        assert h.get('source') == 'splunk'
    finally:
        loop.close()

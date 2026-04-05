from __future__ import annotations

import asyncio

from src.core.hunt.evidence_envelope import EvidenceEnvelope
from src.core.hunt.lane_registry import LaneRegistry
from src.core.hunt.lanes.data_discovery import LANE
from src.core.hunt.hopgraph_queue import drain


def test_hopgraph_enqueue_on_lane_run():
    # Setup a minimal registry and register the lane
    reg = LaneRegistry(config={})
    reg.register(LANE)

    # Create an event that will trigger multiple factors
    evt = {'path_list': [f'/data/secret{i}.csv' for i in range(12)], 'query': 'SELECT * FROM information_schema.tables'}
    env = EvidenceEnvelope(event=evt)

    # Run lanes (synchronous wrapper)
    asyncio.get_event_loop().run_until_complete(reg.run_lanes(env))

    # Drain hopgraph queue and ensure the event signals are present
    items = drain()
    # At least one queued item should exist for the synthesized event id
    assert items and any('signals' in it and isinstance(it['signals'], list) for it in items)

from __future__ import annotations

import asyncio

from src.core.hunt.lanes.data_cloud_api import LANE
from src.core.hunt.evidence_envelope import EvidenceEnvelope


def test_rclone_and_streaming_detection():
    evt = {'user_agent': 'rclone/1.55', 'content_length': 6_000_000}
    env = EvidenceEnvelope(event=evt)
    asyncio.get_event_loop().run_until_complete(LANE.run(env, type('C', (), {'elapsed_ms': lambda self: 2})()))
    names = [f for f in env.all_factors]
    assert 'data:unapproved_rclone_use' in names
    assert 'data:streaming_large_data_via_api' in names


def test_service_account_spike():
    evt = {'service_account': 'svc-123', 'access_count_last_hour': 60}
    env = EvidenceEnvelope(event=evt)
    asyncio.get_event_loop().run_until_complete(LANE.run(env, type('C', (), {'elapsed_ms': lambda self: 2})()))
    names = [f for f in env.all_factors]
    assert 'data:service_account_data_access_spike' in names

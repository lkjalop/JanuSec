from __future__ import annotations

import asyncio

from src.core.hunt.lanes.data_insider import LANE
from src.core.hunt.evidence_envelope import EvidenceEnvelope


def test_privileged_export_and_scheduled_task():
    evt = {'user_role': 'db_admin', 'db_export': True, 'scheduled_task': True, 'transfer_size': 6_000_000}
    env = EvidenceEnvelope(event=evt)
    asyncio.get_event_loop().run_until_complete(LANE.run(env, type('C', (), {'elapsed_ms': lambda self: 1})()))
    names = [f for f in env.all_factors]
    assert 'data:privileged_db_export' in names
    assert 'data:scheduled_task_data_exfil' in names


def test_host_to_cloud_sync_ratio():
    evt = {'host_cloud_sync_ratio': 3.0}
    env = EvidenceEnvelope(event=evt)
    asyncio.get_event_loop().run_until_complete(LANE.run(env, type('C', (), {'elapsed_ms': lambda self: 1})()))
    names = [f for f in env.all_factors]
    assert 'data:host_to_cloud_sync_ratio_anomaly' in names

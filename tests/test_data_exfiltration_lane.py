from __future__ import annotations

import asyncio

from src.core.hunt.lanes.data_exfiltration import LANE
from src.core.hunt.evidence_envelope import EvidenceEnvelope


def test_mass_upload_and_s3_puts():
    evt = {'outbound_bytes': 20_000_000, 'service': 'aws_s3', 'http_method': 'PUT', 'path': '/upload'}
    env = EvidenceEnvelope(event=evt)
    asyncio.get_event_loop().run_until_complete(LANE.run(env, type('C', (), {'elapsed_ms': lambda self: 4})()))
    names = [f for f in env.all_factors]
    assert 'data:mass_upload_to_cloud_service' in names
    assert 'data:unusual_s3_put_pattern' in names


def test_ftp_and_tor_detection():
    evt = {'protocol': 'ftp', 'dst_ip': '8.8.8.8', 'dst_internal': False, 'tor_detected': True}
    env = EvidenceEnvelope(event=evt)
    asyncio.get_event_loop().run_until_complete(LANE.run(env, type('C', (), {'elapsed_ms': lambda self: 4})()))
    names = [f for f in env.all_factors]
    assert 'data:ftp_upload_unusual' in names
    assert 'data:tor_usage' in names

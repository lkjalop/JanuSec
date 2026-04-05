import os
from src.api.artifact_endpoints import _artifact_from_decision


def test_artifact_includes_dread():
    # Build a fake decision object (dict-like)
    dec = {
        'event_id': 'evt-123',
        'verdict': 'ALERT',
        'confidence': 0.82,
        'factors': ['impact:ransomware', 'exfiltration:c2_channel', {'type':'api:auth_bypass','weight':0.8}],
        'hash': 'deadbeef',
        'host_count': 2,
        'tenant_id': 'unit-test',
    }
    art = _artifact_from_decision(dec)
    assert art.get('id') == 'evt-123'
    # DREAD fields should be present
    assert 'dread' in art
    assert 'dread_score' in art
    assert 'dread_severity' in art
    # dread_score is numeric between 0 and 1 or None
    ds = art.get('dread_score')
    assert ds is None or (isinstance(ds, float) and 0.0 <= ds <= 1.0)
    sev = art.get('dread_severity')
    assert sev in (None, 'low', 'medium', 'high')

from src.collectors.client import build_telemetry_payload


def test_build_payload_minimal():
    p = build_telemetry_payload('c1', 'crashed')
    assert p['collector_id'] == 'c1'
    assert p['status'] == 'crashed'
    assert 'ts' in p

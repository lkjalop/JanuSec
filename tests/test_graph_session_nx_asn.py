import os
from collections import deque
from fastapi.testclient import TestClient

from src.api.app import app


def test_nxdomain_and_asn_heuristics(monkeypatch):
    monkeypatch.setenv('TEST_HELPERS_ENABLED', '1')
    client = TestClient(app)

    from src.api.runtime_state import get_file_batch_analysis, get_server_runtime_state
    runtime = get_server_runtime_state(app)
    file_batches = get_file_batch_analysis(runtime)
    # No file batches needed for NX/ASN test

    # Seed nx_rate_tracker to simulate high NXDOMAIN rate for producer 'zeek:10.0.0.1'
    runtime.nx_rate_tracker.clear()
    runtime.nx_rate_tracker['zeek:10.0.0.1'].extend([True]*40 + [False]*10)
    runtime.nx_threshold_cache = 0.3

    # Seed asn_tracker with a rare ASN
    if not hasattr(runtime, 'asn_tracker') or runtime.asn_tracker is None:
        runtime.asn_tracker = {'AS65001': deque(['x'])}
    runtime.asn_tracker['AS65001'] = ['obs']  # rare
    runtime.asn_tracker['AS64500'] = ['a']*10  # common to raise average

    payload = {'session_ids': [], 'correlate': False, 'ewma': False}
    # Using build endpoint should still accept session_ids missing but we expect factors from runtime
    r = client.post('/api/v1/graph/session/build', json={'session_ids': ['batch-missing'], 'correlate': False, 'ewma': False})
    assert r.status_code == 200, r.text
    s = r.json().get('summary')
    # Look for nxdomain_rate_high factor
    found_nx = any(f.get('factor') == 'nxdomain_rate_high' for f in s.get('factors', []))
    assert found_nx
    # Look for asn_rare factor
    found_asn = any(f.get('factor') == 'asn_rare' for f in s.get('factors', []))
    assert found_asn


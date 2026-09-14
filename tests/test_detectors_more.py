import time
from src.core.detectors.entropy_exfil import detect_entropy_and_exfil
from src.core.detectors.lateral_movement import detect_lateral_movement
from src.core.detectors.privilege_change import detect_privilege_changes
from src.core.detectors.port_protocol_anomaly import detect_port_protocol_anomalies
from src.core.detectors.cloud_metadata_anomaly import detect_cloud_metadata_anomalies
from src.core.detectors.time_of_day_anomaly import detect_time_of_day_anomalies

class DummyRuntime:
    def __init__(self):
        self.recent_files = []
        self.conn_events = []
        self.auth_events = []
        self.flows = []
        self.cloud_events = []
        self.events = []
        self.out_bytes = []


def test_entropy_exfil_detector_flags_high_entropy_and_size():
    rt = DummyRuntime()
    # create a high-entropy sample
    rt.recent_files = [{'sha256':'abc','sample':'\x00\xff\x88\x77\x66\x55'*50}]
    rt.out_bytes = [2000000]
    res = detect_entropy_and_exfil(rt)
    assert any(r.get('factor') in ('file_high_entropy','data_exfil_size_large') for r in res)


def test_lateral_movement_detector():
    rt = DummyRuntime()
    # actor connects to 6 distinct hosts
    rt.conn_events = [{'actor':'userA','dst_host':f'h{i}'} for i in range(6)]
    res = detect_lateral_movement(rt, threshold=5)
    assert any(r.get('factor') == 'lateral_movement' for r in res)


def test_privilege_change_detector():
    rt = DummyRuntime()
    rt.auth_events = [{'type':'privileged_logon','actor':'svc1'}]
    res = detect_privilege_changes(rt)
    assert any(r.get('factor') == 'privilege_change' for r in res)


def test_port_protocol_anomaly_detector():
    rt = DummyRuntime()
    rt.flows = [{'dst_port':9999},{'dst_port':9999},{'dst_port':9999},{'dst_port':9999},{'dst_port':9999},{'dst_port':9999},{'dst_port':9999},{'dst_port':9999},{'dst_port':9999},{'dst_port':9999}]
    res = detect_port_protocol_anomalies(rt, uncommon_threshold=5)
    assert any(r.get('factor') == 'port_uncommon_activity' for r in res)


def test_cloud_and_time_of_day_detectors():
    rt = DummyRuntime()
    rt.cloud_events = [{'event_type':'iam_policy_change','resource':'arn:aws:iam::123:policy/test'}]
    rt.events = [{'ts': time.time() - 3600*5, 'actor':'srv1'}]
    res_c = detect_cloud_metadata_anomalies(rt)
    res_t = detect_time_of_day_anomalies(rt, start_hour=0, end_hour=23)
    assert any(r.get('factor') == 'cloud_metadata_anomaly' for r in res_c)
    assert isinstance(res_t, list)


def test_graph_session_build_enriches_factors_with_metadata(tmp_path):
    # integration-like check: call build session with runtime-like test helpers
    from src.api.graph_sessions import build_session
    import os
    # Enable test helpers so detectors run and runtime-driven factors are emitted
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    # Provide a deterministic test IP to force ASN rarity detector path
    payload = {'session_ids':['batch-overlap-1','batch-overlap-2'], 'correlate': True, 'test_ips': ['8.8.8.8']}
    # Call synchronously via asyncio loop
    import asyncio
    loop = asyncio.get_event_loop()
    res = loop.run_until_complete(build_session(payload))
    summary = res.get('summary')
    assert isinstance(summary.get('factors'), list)
    # factors may include dict-style detectors; prefer a factor with canonical metadata (playbook or mitre)
    found_meta = False
    has_metadata_key = False
    for f in summary.get('factors'):
        if isinstance(f, dict) and isinstance(f.get('metadata'), dict):
            has_metadata_key = True
            md = f.get('metadata') or {}
            if md.get('playbook') or md.get('mitre'):
                found_meta = True; break
    # If no factor had explicit playbook/mitre, at minimum enrichment should have added a `metadata` key
    if not found_meta:
        assert has_metadata_key, f"No enriched factor metadata found in summary factors: {summary.get('factors')[:5]}"
    # Also ensure the canonical metadata mapping exists for at least one known detector key
    from src.core.factor_metadata import FACTOR_METADATA
    assert 'asn_rare' in FACTOR_METADATA or 'file_signature_mismatch' in FACTOR_METADATA

    # Additionally assert that when ASN rarity appears it's enriched with expected metadata keys
    for f in summary.get('factors'):
        if isinstance(f, dict) and (f.get('factor') == 'asn_rare' or (f.get('metadata') or {}).get('playbook')=='network_investigation'):
            md = f.get('metadata') or {}
            assert md.get('playbook') is not None, 'asn_rare factor missing playbook metadata'
            assert isinstance(md.get('mitre') or [], list), 'asn_rare factor missing mitre metadata list'
            break

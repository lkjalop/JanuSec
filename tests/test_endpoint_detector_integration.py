import asyncio
import types
import pytest
from src.api import graph_sessions
from src.core.detectors import endpoint_ransom


def test_endpoint_detectors_return_factors():
    # call detectors directly with synthetic runtime dict
    runtime = {
        'process_events': [
            {'exe':'/usr/bin/rarechild','parent_exe':'/usr/bin/normal','host':'host-a'},
            {'exe':'/usr/bin/rarechild','parent_exe':'/usr/bin/normal','host':'host-b'},
            {'exe':'/usr/bin/common','parent_exe':'/usr/bin/normal','host':'host-a'},
        ],
        'file_events': [ {'host':'host-a','path':'C:/data/file.locked'} for _ in range(60) ],
        'network_events': [ {'exe':'/tmp/unsigned','outbound':True,'binary_signed':False,'host':'host-a'} ]
    }
    rp = endpoint_ransom.detect_rare_parent_child(runtime)
    fw = endpoint_ransom.detect_file_encryption_wave(runtime)
    ul = endpoint_ransom.detect_unsigned_network_launch(runtime)
    assert isinstance(rp, list) and any(isinstance(x, dict) and x.get('factor')=='rare_parent_child' for x in rp)
    assert isinstance(fw, list) and any(isinstance(x, dict) and x.get('factor')=='file_encryption_wave' for x in fw)
    assert isinstance(ul, list) and any(isinstance(x, dict) and x.get('factor')=='unsigned_binary_network_launch' for x in ul)


def test_build_session_appends_detector_factors(monkeypatch):
    # Provide a fake runtime via monkeypatching get_server_runtime_state to return our runtime
    runtime = {
        'process_events': [{'exe':'/usr/bin/rarechild','parent_exe':'/usr/bin/normal','host':'host-a'}],
        'file_events': [{'host':'host-a','path':'/tmp/file.locked'} for _ in range(60)],
        'network_events': [{'exe':'/tmp/unsigned','outbound':True,'binary_signed':False,'host':'host-a'}]
    }
    # pass runtime_override directly to build_session (new optional param)
    payload = {'session_ids':['batch-overlap-1'], 'correlate': False, 'ewma': False }
    res = asyncio.get_event_loop().run_until_complete(graph_sessions.build_session(payload, runtime_override=runtime))
    summary = res.get('summary') or res
    factors = summary.get('factors') or []
    names = [f.get('factor') if isinstance(f, dict) else f for f in factors]
    assert any(n in ('rare_parent_child','file_encryption_wave','unsigned_binary_network_launch') for n in names)

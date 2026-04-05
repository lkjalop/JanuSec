from src.core.correlation.rules.registry import register_rule as _priority_register


@_priority_register('suspicious_rundll32_usage', mitre=['T1218.011'], factors_required=['process','cmdline'], window_seconds=60, severity=6, confidence_boost=0.2)
def suspicious_rundll32_usage(event):
    cmd = event.get('cmdline','').lower()
    if 'rundll32' in event.get('process','').lower() and ('.dll,' in cmd or '.dll"' in cmd or '/s' in cmd):
        return True
    return False


@_priority_register('one_drive_unauthorized_sync', mitre=['T1537'], factors_required=['file','user','process'], window_seconds=3600, severity=5, confidence_boost=0.15)
def one_drive_unauthorized_sync(event):
    proc = event.get('process','').lower()
    file = event.get('file','').lower()
    if 'onedrive' in proc and file.endswith('.enc'):
        return True
    return False


@_priority_register('staged_scripts_in_temp', mitre=['T1059'], factors_required=['path','process'], window_seconds=300, severity=5, confidence_boost=0.15)
def staged_scripts_in_temp(event):
    path = event.get('path','').lower()
    if '/tmp/' in path or '\\temp\\' in path:
        if path.endswith('.ps1') or path.endswith('.sh') or path.endswith('.bat'):
            return True
    return False


@_priority_register('suspicious_certutil_usage', mitre=['T1119'], factors_required=['process','cmdline'], window_seconds=120, severity=6, confidence_boost=0.2)
def suspicious_certutil_usage(event):
    proc = event.get('process','').lower()
    cmd = event.get('cmdline','').lower()
    if 'certutil' in proc and ('-urlcache' in cmd or '-decode' in cmd):
        return True
    return False


@_priority_register('wevtutil_clear_events', mitre=['T1070.001'], factors_required=['process','cmdline'], window_seconds=60, severity=7, confidence_boost=0.25)
def wevtutil_clear_events(event):
    proc = event.get('process','').lower()
    cmd = event.get('cmdline','').lower()
    if 'wevtutil' in proc and ('cl' in cmd or 'clear-log' in cmd):
        return True
    return False


@_priority_register('autorun_registry_persistence', mitre=['T1547.001'], factors_required=['registry','process'], window_seconds=300, severity=6, confidence_boost=0.2)
def autorun_registry_persistence(event):
    reg = event.get('registry','').lower()
    if 'run' in reg or 'runonce' in reg:
        return True
    return False


@_priority_register('suspicious_schtasks_create', mitre=['T1053.005'], factors_required=['process','cmdline'], window_seconds=120, severity=6, confidence_boost=0.2)
def suspicious_schtasks_create(event):
    proc = event.get('process','').lower()
    cmd = event.get('cmdline','').lower()
    if 'schtasks' in proc and ('/create' in cmd or '/sc' in cmd):
        return True
    return False


@_priority_register('powershell_encoded_command', mitre=['T1059.001'], factors_required=['process','cmdline'], window_seconds=60, severity=7, confidence_boost=0.3)
def powershell_encoded_command(event):
    proc = event.get('process','').lower()
    cmd = event.get('cmdline','') or event.get('command_line','')
    if 'powershell' in proc and ('-enc ' in cmd or '-encodedcommand' in cmd.lower()):
        return True
    return False


@_priority_register('suspicious_at_command', mitre=['T1053.005'], factors_required=['process','cmdline'], window_seconds=120, severity=5, confidence_boost=0.1)
def suspicious_at_command(event):
    proc = event.get('process','').lower()
    cmd = event.get('cmdline','').lower()
    if proc.endswith('at.exe') or ' at ' in cmd:
        return True
    return False


@_priority_register('netstat_listening_high_ports', mitre=['T1049'], factors_required=['process','net'], window_seconds=60, severity=4, confidence_boost=0.05)
def netstat_listening_high_ports(event):
    net = event.get('net','')
    # simplistic parsing: expect 'LISTENING:port'
    try:
        if isinstance(net, str) and ':' in net:
            parts = net.split(':')
            port = int(parts[-1])
            if port >= 1024:
                return True
    except Exception:
        return False
    return False

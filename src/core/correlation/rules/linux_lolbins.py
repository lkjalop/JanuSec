from typing import Dict, Any
from .registry import register_rule


@register_rule(name='linux_suspicious_curl_exec', mitre=['T1059.003'], factors_required=['process','command_line'], window_seconds=3600, severity='medium', confidence_boost=0.2)
def linux_suspicious_curl_exec(event: Dict[str, Any]) -> bool:
    proc = str(event.get('process') or '').lower()
    cmd = str(event.get('command_line') or '').lower()
    if any(x in proc for x in ('curl','wget')) and ('| bash' in cmd or 'bash -c' in cmd or '-s' in cmd or '-o-' in cmd):
        return True
    return False


@register_rule(name='linux_cron_network_tool', mitre=['T1053'], factors_required=['scheduled_job','command_line'], window_seconds=86400, severity='medium', confidence_boost=0.15)
def linux_cron_network_tool(event: Dict[str, Any]) -> bool:
    if event.get('scheduled_job') and any(x in str(event.get('command_line') or '').lower() for x in ('curl','wget','python -c')):
        return True
    return False


@register_rule(name='linux_bash_temp_exec', mitre=['T1059.004'], factors_required=['process','cwd'], window_seconds=3600, severity='medium', confidence_boost=0.18)
def linux_bash_temp_exec(event: Dict[str, Any]) -> bool:
    proc = str(event.get('process') or '').lower()
    cwd = str(event.get('cwd') or '').lower()
    if 'bash' in proc and ('/tmp' in cwd or '/var/tmp' in cwd or '/dev/shm' in cwd):
        return True
    return False


@register_rule(name='linux_downloads_exec_sh', mitre=['T1204'], factors_required=['process','path'], window_seconds=3600, severity='medium', confidence_boost=0.12)
def linux_downloads_exec_sh(event: Dict[str, Any]) -> bool:
    path = str(event.get('path') or '').lower()
    proc = str(event.get('process') or '').lower()
    if any(x in path for x in ('/home/', '/downloads', '/tmp')) and any(x in proc for x in ('sh','bash','python')):
        if 'downloads' in path or path.endswith('.sh'):
            return True
    return False


@register_rule(name='linux_chmod_exec_downloads', mitre=['T1547'], factors_required=['file_action','path'], window_seconds=3600, severity='medium', confidence_boost=0.2)
def linux_chmod_exec_downloads(event: Dict[str, Any]) -> bool:
    action = str(event.get('file_action') or '').lower()
    path = str(event.get('path') or '').lower()
    if action in ('chmod_x','make_executable') and ('/downloads' in path or '/tmp' in path):
        return True
    return False


@register_rule(name='linux_systemctl_user_unusual', mitre=['T1543'], factors_required=['process','command_line'], window_seconds=3600, severity='high', confidence_boost=0.25)
def linux_systemctl_user_unusual(event: Dict[str, Any]) -> bool:
    cmd = str(event.get('command_line') or '').lower()
    if 'systemctl --user' in cmd and any(x in cmd for x in ('enable','bootstrap','link','start')):
        return True
    return False


@register_rule(name='linux_sudo_misuse_pattern', mitre=['T1548'], factors_required=['process','user'], window_seconds=3600, severity='high', confidence_boost=0.25)
def linux_sudo_misuse_pattern(event: Dict[str, Any]) -> bool:
    proc = str(event.get('process') or '').lower()
    user = str(event.get('user') or '').lower()
    if proc.startswith('sudo') and user not in ('root','admin'):
        # heuristic: non-root users invoking sudo with network tools or shell
        cmd = str(event.get('command_line') or '').lower()
        if any(x in cmd for x in ('curl','wget','bash -c','python -c','/tmp')):
            return True
    return False


@register_rule(name='linux_sh_from_tmp', mitre=['T1059'], factors_required=['process','cwd'], window_seconds=3600, severity='medium', confidence_boost=0.18)
def linux_sh_from_tmp(event: Dict[str, Any]) -> bool:
    proc = str(event.get('process') or '').lower()
    cwd = str(event.get('cwd') or '').lower()
    if proc in ('sh','bash') and any(x in cwd for x in ('/tmp','/var/tmp','/dev/shm')):
        return True
    return False


@register_rule(name='linux_python_exec_downloads', mitre=['T1059.006'], factors_required=['process','path'], window_seconds=3600, severity='medium', confidence_boost=0.18)
def linux_python_exec_downloads(event: Dict[str, Any]) -> bool:
    proc = str(event.get('process') or '').lower()
    path = str(event.get('path') or '').lower()
    if 'python' in proc and any(x in path for x in ('/downloads','/tmp','/home/')):
        return True
    return False

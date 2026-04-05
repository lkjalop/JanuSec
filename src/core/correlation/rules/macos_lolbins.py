from typing import Dict, Any
from .registry import register_rule


@register_rule(name='macos_osascript_network_payload', mitre=['T1059.007'], factors_required=['process','command_line'], window_seconds=3600, severity='high', confidence_boost=0.25)
def macos_osascript_network_payload(event: Dict[str, Any]) -> bool:
    proc = str(event.get('process') or '').lower()
    cmd = str(event.get('command_line') or '').lower()
    if 'osascript' in proc and any(x in cmd for x in ('http','https','curl','wget','download')):
        return True
    return False


@register_rule(name='macos_open_from_downloads', mitre=['T1204.002'], factors_required=['process','path'], window_seconds=3600, severity='medium', confidence_boost=0.18)
def macos_open_from_downloads(event: Dict[str, Any]) -> bool:
    proc = str(event.get('process') or '').lower()
    path = str(event.get('path') or '').lower()
    if 'open' in proc and any(x in path for x in ('/downloads','/tmp','/var/folders')):
        return True
    return False


@register_rule(name='macos_launchctl_unusual', mitre=['T1543'], factors_required=['process','command_line'], window_seconds=3600, severity='high', confidence_boost=0.25)
def macos_launchctl_unusual(event: Dict[str, Any]) -> bool:
    cmd = str(event.get('command_line') or '').lower()
    if 'launchctl' in cmd and any(x in cmd for x in ('bootstrap','load','enable','kickstart','submit')):
        return True
    return False


@register_rule(name='macos_persistence_writes_userdirs', mitre=['T1547'], factors_required=['file_action','path'], window_seconds=86400, severity='medium', confidence_boost=0.18)
def macos_persistence_writes_userdirs(event: Dict[str, Any]) -> bool:
    action = str(event.get('file_action') or '').lower()
    path = str(event.get('path') or '').lower()
    if action in ('write','create') and any(x in path for x in ('/users/','/applications/','/library/launchagents','/library/launchdaemons','/users/')):
        return True
    return False


@register_rule(name='macos_curl_wget_exec_downloads', mitre=['T1059.003'], factors_required=['process','path','command_line'], window_seconds=3600, severity='medium', confidence_boost=0.18)
def macos_curl_wget_exec_downloads(event: Dict[str, Any]) -> bool:
    proc = str(event.get('process') or '').lower()
    path = str(event.get('path') or '').lower()
    cmd = str(event.get('command_line') or '').lower()
    if any(x in proc for x in ('curl','wget','python')) and any(x in path for x in ('/downloads','/tmp')) and any(x in cmd for x in ('| python','| bash','-o -','-s')):
        return True
    return False


@register_rule(name='macos_disk_image_mount_exec', mitre=['T1204'], factors_required=['event','path'], window_seconds=3600, severity='medium', confidence_boost=0.18)
def macos_disk_image_mount_exec(event: Dict[str, Any]) -> bool:
    ev = str(event.get('event') or '').lower()
    path = str(event.get('path') or '').lower()
    if 'mount' in ev and path.endswith('.dmg'):
        return True
    return False


@register_rule(name='macos_python_exec_from_downloads', mitre=['T1059.006'], factors_required=['process','path'], window_seconds=3600, severity='medium', confidence_boost=0.18)
def macos_python_exec_from_downloads(event: Dict[str, Any]) -> bool:
    proc = str(event.get('process') or '').lower()
    path = str(event.get('path') or '').lower()
    if 'python' in proc and any(x in path for x in ('/downloads','/tmp','/users/')):
        return True
    return False


@register_rule(name='macos_launchd_write_user', mitre=['T1547.001'], factors_required=['file_action','path'], window_seconds=86400, severity='high', confidence_boost=0.22)
def macos_launchd_write_user(event: Dict[str, Any]) -> bool:
    action = str(event.get('file_action') or '').lower()
    path = str(event.get('path') or '').lower()
    if action in ('write','create') and 'launchagents' in path:
        return True
    return False

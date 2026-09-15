from __future__ import annotations

import re
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='exec_scheduled_task_lolbin_anomaly', mitre=['T1053'], factors_required=['scheduled_task','command_line'], window_seconds=86400, severity='medium', confidence_boost=0.25)
def exec_scheduled_task_lolbin_anomaly(event: Dict[str, Any]) -> bool:
    task = event.get('scheduled_task')
    cmd = str(event.get('command_line') or '').lower()
    if task and any(x in cmd for x in ('mshta','bitsadmin','powershell','curl','wget')):
        return True
    return False


@register_rule(name='corr_scheduled_task_lolbin', mitre=['T1053.005','T1204'], factors_required=['process','cmdline','schedule'], window_seconds=3600, severity='medium', confidence_boost=0.2)
def scheduled_task_lolbin(event: Dict[str, Any]) -> bool:
    try:
        proc = str(event.get('process') or '')
        cmd = str(event.get('cmdline') or event.get('command_line') or '')
        schedule = event.get('schedule') or {}
        # detect known LOLBins scheduled to run scripts
        if re.search(r'(mshta|wscript|cscript|powershell|rundll32|schtasks)\b', proc, re.IGNORECASE):
            if schedule:
                return True
            if re.search(r'\.(vbs|ps1|js)\b', cmd, re.IGNORECASE):
                return True
            if re.search(r'(mshta|wscript|cscript|powershell|rundll32)\b', cmd, re.IGNORECASE):
                return True
    except Exception:
        return False
    return False

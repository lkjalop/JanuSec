from __future__ import annotations

import re
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='exec_office_to_powershell_parent_child', mitre=['T1059'], factors_required=['parent_process','child_process'], window_seconds=3600, severity='high', confidence_boost=0.35)
def exec_office_to_powershell_parent_child(event: Dict[str, Any]) -> bool:
    parent = str(event.get('parent_process') or '').lower()
    child = str(event.get('child_process') or '').lower()
    if any(x in parent for x in ('excel','winword','powerpoint','outlook')) and 'powershell' in child:
        return True
    return False


@register_rule(name='corr_office_spawn_ps', mitre=['T1204','T1059.001'], factors_required=['file','process','cmdline'], window_seconds=600, severity='high', confidence_boost=0.35)
def office_spawn_ps(event: Dict[str, Any]) -> bool:
    """Detect Office document -> powershell spawn via macro/drop chain."""
    try:
        src = str(event.get('event.source') or event.get('source') or '')
        proc = str(event.get('process') or event.get('child_process') or '')
        parent_proc = str(event.get('parent_process') or '')
        cmd = str(event.get('cmdline') or event.get('command_line') or '')
        office_parent_match = re.search(r'excel(?:\.exe)?|winword(?:\.exe)?|powerpnt(?:\.exe)?', parent_proc, re.IGNORECASE)
        if re.search(r'\.(docm|xlsm|pptm)\b|vbaProject', src, re.IGNORECASE) or office_parent_match:
            if 'powershell' in proc.lower() or 'powershell' in parent_proc.lower() or re.search(r'EncodedCommand|base64', cmd, re.IGNORECASE):
                return True
    except Exception:
        return False
    return False

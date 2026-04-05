from __future__ import annotations

import re
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='exec_powershell_encoded_command', mitre=['T1059.001'], factors_required=['command_line'], window_seconds=3600, severity='high', confidence_boost=0.4)
def exec_powershell_encoded_command(event: Dict[str, Any]) -> bool:
    cmd = str(event.get('command_line') or '').lower()
    if 'powershell' in cmd and ('-enc ' in cmd or '-encodedcommand' in cmd or '[convert]::frombase64string' in cmd):
        return True
    return False


@register_rule(name='exec_powershell_encoded', mitre=['T1059.001'], factors_required=['command_line'], window_seconds=3600, severity='high', confidence_boost=0.35)
def exec_powershell_encoded(event: Dict[str, Any]) -> bool:
    return exec_powershell_encoded_command(event)


@register_rule(name='powershell_encoded_command', mitre=['T1059.001'], factors_required=['process','cmdline'], window_seconds=300, severity='medium', confidence_boost=0.25)
@register_rule(name='corr_powershell_encoded', mitre=['T1059.001'], factors_required=['process','cmdline'], window_seconds=300, severity='medium', confidence_boost=0.25)
def powershell_encoded(event: Dict[str, Any]) -> bool:
    try:
        proc = str(event.get('process') or '')
        cmd = str(event.get('cmdline') or event.get('command_line') or '')
        if 'powershell' in proc.lower() or 'pwsh' in proc.lower():
            if re.search(r'-EncodedCommand|-encodedcommand|-enc\b|-e\s|ConvertFrom-Base64|base64', cmd, re.IGNORECASE) or len(cmd) > 200:
                return True
    except Exception:
        return False
    return False

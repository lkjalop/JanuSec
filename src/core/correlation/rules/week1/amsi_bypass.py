from __future__ import annotations

import re
from typing import Any, Dict
from ..registry import register_rule


_AMSI_PATTERNS = [
    re.compile(p, re.I) for p in [
        r'AmsiUtils',
        r'AmsiScanBuffer',
        r'Set-Item\s+Property:\\HKLM',
        r'Reflection\.Assembly.*Load',
        r'AMSIInitFailed',
        r'System\.Management\.Automation',
        r'FromBase64String\([A-Za-z0-9+/=]{20,}',
        r'ExecutionPolicy\s*Bypass',
        r'\b-NoProfile\b',
    ]
]


def _looks_like_amso_bypass(event: Dict[str, Any]) -> bool:
    proc = event.get("process")
    if isinstance(proc, dict):
        cmd = proc.get("cmdline", "") or ""
    else:
        cmd = str(event.get("cmdline") or event.get("command_line") or "")
    if "-EncodedCommand" in cmd and "powershell" in cmd.lower():
        return True
    if "amsi" in cmd.lower() and ("set-itemproperty" in cmd.lower() or "amsi.dll" in cmd.lower()):
        return True
    return False


@register_rule(name='exec_amsi_bypass_pattern', mitre=['T1059.001'], factors_required=['command_line'], window_seconds=3600, severity='high', confidence_boost=0.4)
def exec_amsi_bypass_pattern(event: Dict[str, Any]) -> bool:
    cmd = str(event.get('command_line') or event.get('cmdline') or '').lower()
    if 'amsi' in cmd or 'antimal' in cmd or 'amsienabled' in cmd:
        return True
    return False


@register_rule(name='powershell_amsi_bypass_pattern', mitre=['T1204','T1059.001'], factors_required=['process','cmdline','file'], window_seconds=600, severity='high', confidence_boost=0.4)
@register_rule(name='corr_amsi_bypass', mitre=['T1204','T1059.001'], factors_required=['process','cmdline','file'], window_seconds=600, severity='high', confidence_boost=0.4)
def corr_amsi_bypass(event: Dict[str, Any]) -> bool:
    try:
        cmd = str(event.get('cmdline') or event.get('command_line') or '')
        src = str(event.get('event.source') or event.get('source') or '')
        if any(p.search(cmd) for p in _AMSI_PATTERNS):
            return True
        if any(p.search(src) for p in _AMSI_PATTERNS):
            return True
        if 'powershell' in cmd.lower() and ('-encodedcommand' in cmd.lower() or len(cmd) > 200):
            return True
    except Exception:
        return False
    return False


@register_rule(name='week1:amsi_bypass', mitre=['T1059.001'], factors_required=['process','parent'], window_seconds=3600, severity='medium', confidence_boost=0.2)
def amsi_bypass_rule(event: Dict[str, Any]) -> bool:
    """Conservative AMSI bypass detector used for week1 rule set."""
    try:
        if _looks_like_amso_bypass(event):
            return True
        parent = event.get("parent")
        parent_cmd = parent.get("cmdline", "") if isinstance(parent, dict) else ""
        proc = event.get("process")
        proc_exe = proc.get("exe", "") if isinstance(proc, dict) else str(proc or "")
        if "winword" in parent_cmd.lower() and "powershell" in proc_exe.lower():
            return True
        # fallback: pattern-based correlation
        return corr_amsi_bypass(event)
    except Exception:
        return False


# Backwards compatibility alias
amsi_bypass = amsi_bypass_rule


"""Week-1 endpoint rules: Office Macro→PowerShell, AMSI bypass,
Encoded PowerShell, Scheduled Task LOLBin.

These detectors scan sanitized runtime events for lightweight signals.
Each detector returns a list of factor dicts: {'factor','score','producer',...}.
"""
from __future__ import annotations
from typing import Any, Dict, List
import re

PRODUCER = 'week1_rules'

_OFFICE_PARENTS = {
    'winword.exe','excel.exe','powerpnt.exe','outlook.exe','onenote.exe','visio.exe'
}

_PS_NAMES = {'powershell.exe','pwsh.exe'}

_AMSI_PATTERNS = [
    r"(?i)System\.Management\.Automation\.AmsiUtils",
    r"(?i)amsi(init|utils|bypass|disable)",
    r"(?i)Add-MpPreference\s+-DisableRealtimeMonitoring",
    r"(?i)Reflection\.Assembly\s*::\s*Load",
    r"(?i)FromBase64String\s*\(",
    r"(?i)IEX\s*\((New-Object|Invoke-WebRequest)",
]

_ENCODED_PS_PATTERNS = [
    r"(?i)\bpowershell\b.*\s-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]+",
    r"(?i)\bpwsh\b.*\s-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]+",
]

def _lower(x: Any) -> str:
    try:
        return str(x or '').lower()
    except Exception:
        return ''

def _get(ev: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = ev.get(k)
        if isinstance(v, str) and v:
            return v
    return ''

def _match_any(text: str, patterns: List[str]) -> bool:
    if not text:
        return False
    for p in patterns:
        try:
            if re.search(p, text):
                return True
        except Exception:
            continue
    return False

def detect_office_macro_powershell(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if runtime is None:
        return out
    try:
        events = list(getattr(runtime, 'sanitized_events', []) or [])
    except Exception:
        events = []
    for ev in events:
        pname = _lower(_get(ev, 'process_name','image','process'))
        parent = _lower(_get(ev, 'parent_name','parent_process','parent'))
        cmd = _get(ev, 'cmdline','command_line','args')
        if pname in _PS_NAMES and parent in _OFFICE_PARENTS:
            score = 0.85
            # Boost when macro-enabled attachment observed in context
            try:
                fn = _lower(_get(ev, 'filename','attachment_name','file_name'))
                if fn.endswith('.docm') or fn.endswith('.xlsm') or fn.endswith('.pptm'):
                    score = 0.92
            except Exception:
                pass
            out.append({
                'factor': 'office_macro_powershell',
                'score': score,
                'producer': PRODUCER,
                'parent': parent,
                'child': pname,
                'cmdline': cmd[:300] if isinstance(cmd, str) else None
            })
    return out

def detect_amsi_bypass(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if runtime is None:
        return out
    try:
        events = list(getattr(runtime, 'sanitized_events', []) or [])
    except Exception:
        events = []
    for ev in events:
        cmd = _get(ev, 'cmdline','command_line','args')
        if not isinstance(cmd, str) or not cmd:
            continue
        if _match_any(cmd, _AMSI_PATTERNS):
            out.append({
                'factor': 'amsi_bypass',
                'score': 0.9,
                'producer': PRODUCER,
                'cmdline': cmd[:500]
            })
    return out

def detect_encoded_powershell(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if runtime is None:
        return out
    try:
        events = list(getattr(runtime, 'sanitized_events', []) or [])
    except Exception:
        events = []
    for ev in events:
        cmd = _get(ev, 'cmdline','command_line','args')
        pname = _lower(_get(ev, 'process_name','image','process'))
        if not isinstance(cmd, str):
            continue
        if pname in _PS_NAMES and _match_any(cmd, _ENCODED_PS_PATTERNS):
            out.append({
                'factor': 'encoded_powershell',
                'score': 0.82,
                'producer': PRODUCER,
                'cmdline': cmd[:500]
            })
    return out

def detect_scheduled_task_lolbin(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if runtime is None:
        return out
    try:
        events = list(getattr(runtime, 'sanitized_events', []) or [])
    except Exception:
        events = []
    for ev in events:
        pname = _lower(_get(ev, 'process_name','image','process'))
        cmd = _get(ev, 'cmdline','command_line','args')
        if pname == 'schtasks.exe' and isinstance(cmd, str):
            c = cmd.lower()
            if (' /create ' in c or ' /run ' in c) and ('powershell' in c or 'cmd.exe' in c or 'wscript' in c):
                out.append({
                    'factor': 'scheduled_task_lolbin',
                    'score': 0.78,
                    'producer': PRODUCER,
                    'cmdline': cmd[:400]
                })
    return out

__all__ = [
    'detect_office_macro_powershell',
    'detect_amsi_bypass',
    'detect_encoded_powershell',
    'detect_scheduled_task_lolbin'
]

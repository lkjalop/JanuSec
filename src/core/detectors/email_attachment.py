from __future__ import annotations
from typing import Any, Dict, List
try:
    from src.core.attachment_analyzer import analyze_attachments as _analyze_runtime_attachments  # type: ignore
except Exception:
    _analyze_runtime_attachments = None

PRODUCER = 'email_attachment_analyzer'

MACRO_EXT = {'.docm','.xlsm','.pptm'}
EXEC_EXT = {'.exe','.dll','.js','.vbs','.ps1','.bat','.cmd','.msi','.hta'}


def _lower(x: Any) -> str:
    try:
        return str(x or '').lower()
    except Exception:
        return ''


def analyze_email_attachments(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if runtime is None:
        return out
    # Integrate runtime attachment analysis when available
    try:
        if _analyze_runtime_attachments:
            for rec in (_analyze_runtime_attachments(runtime) or []):
                try:
                    rec.setdefault('producer', PRODUCER)
                    out.append(rec)
                except Exception:
                    pass
    except Exception:
        pass
    events = list(getattr(runtime, 'sanitized_events', []) or [])
    for ev in events:
        domain = _lower(ev.get('domain') or ev.get('source_type'))
        if domain and domain != 'email':
            continue
        atts = ev.get('attachments') or ev.get('email_attachments') or []
        if not isinstance(atts, list):
            continue
        for a in atts:
            fn = _lower(a.get('filename') if isinstance(a, dict) else a)
            if not fn:
                continue
            for ext in MACRO_EXT:
                if fn.endswith(ext):
                    out.append({'factor':'email_attachment_macro','score':0.7,'producer':PRODUCER,'filename':fn})
                    break
            for ext in EXEC_EXT:
                if fn.endswith(ext):
                    out.append({'factor':'email_attachment_executable','score':0.75,'producer':PRODUCER,'filename':fn})
                    break
    return out

__all__ = ['analyze_email_attachments']

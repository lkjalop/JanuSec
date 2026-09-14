from __future__ import annotations

from typing import Any, Dict


def redact_event(ev: Dict[str, Any], mode: str = 'none') -> Dict[str, Any]:
    if mode not in {'mask','none'}:
        mode = 'none'
    if mode == 'none':
        return dict(ev)
    out = {}
    for k, v in ev.items():
        if isinstance(v, str):
            if '@' in v:
                out[k] = v[:2] + '***' + v[-2:]
            elif len(v) > 8:
                out[k] = v[:2] + '***' + v[-2:]
            else:
                out[k] = '***'
        else:
            out[k] = v
    return out


def redact_for_llm(payload: Dict[str, Any], sensitive_fields: list[str] | None = None) -> Dict[str, Any]:
    """Redact sensitive fields before sending to LLM. sensitive_fields is a list
    of keys to redact (top-level). This is a lightweight helper used by LLM
    prompt builders to avoid leaking secrets/PII.
    """
    if not sensitive_fields:
        sensitive_fields = []
    out = {}
    for k, v in payload.items():
        if k in sensitive_fields:
            out[k] = 'REDACTED'
        else:
            # mask emails/keys inline
            if isinstance(v, str) and ('@' in v or len(v) > 100):
                out[k] = v[:24] + '...[REDACTED]'
            else:
                out[k] = v
    return out


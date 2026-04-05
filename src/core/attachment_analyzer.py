from __future__ import annotations

import hashlib
from typing import Any, Dict, List


def _sha256(data: bytes) -> str:
    try:
        h = hashlib.sha256(data).hexdigest()
        return h
    except Exception:
        return ''


def analyze_attachments(runtime) -> List[Dict[str, Any]]:
    """Extract simple attachment facts from runtime email stores and emit factors.

    Expected runtime fields (when available):
    - runtime.email_messages: list of dicts with keys {filename, content, mime, cmdline?}
    """
    res: List[Dict[str, Any]] = []
    msgs = getattr(runtime, 'email_messages', []) or []
    for m in msgs:
        try:
            fn = str(m.get('filename') or '')
            content = m.get('content')
            mime = str(m.get('mime') or '')
            if not fn or content is None:
                continue
            sha = ''
            try:
                if isinstance(content, (bytes, bytearray)):
                    sha = _sha256(bytes(content))
                elif isinstance(content, str):
                    sha = _sha256(content.encode('utf-8', errors='ignore'))
            except Exception:
                sha = ''
            suspicious = False
            score = 0.0
            name_l = fn.lower()
            # Heuristics: macro-bearing office docs, executable-like attachments
            if name_l.endswith(('.docm', '.xlsm', '.pptm')) or ('macro' in mime.lower()):
                suspicious = True
                score = max(score, 0.6)
                res.append({'factor': 'email_attachment_macro', 'filename': fn, 'sha256': sha, 'mime': mime, 'score': score})
            if name_l.endswith(('.exe', '.scr', '.dll', '.ps1', '.hta')):
                suspicious = True
                score = max(score, 0.55)
                res.append({'factor': 'email_attachment_executable', 'filename': fn, 'sha256': sha, 'mime': mime, 'score': score})
            # Suspicious filename tokens
            for tok in ('invoice', 'urgent', 'payment', 'unlock', 'macro'):
                if tok in name_l:
                    suspicious = True
                    score = max(score, 0.45)
                    break
            if suspicious and score > 0.0 and not any(r.get('filename') == fn for r in res):
                res.append({'factor': 'email_attachment_suspicious', 'filename': fn, 'sha256': sha, 'mime': mime, 'score': score})
        except Exception:
            continue
    return res


__all__ = ['analyze_attachments']

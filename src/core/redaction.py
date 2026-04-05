from __future__ import annotations

import re
from typing import Any, Dict, Tuple, List


_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b")
_CARD = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_IP = re.compile(r"\b(?:(?:2[0-5]{2}|1?\d?\d)\.){3}(?:2[0-5]{2}|1?\d?\d)\b")

_CUSTOM_PATTERNS: List[re.Pattern] = []
_DOMAIN_ALLOW: List[str] = []
_IP_ALLOW: List[str] = []

def _load_policy() -> None:
    global _CUSTOM_PATTERNS, _DOMAIN_ALLOW, _IP_ALLOW
    import os
    try:
        raw = os.getenv('PII_CUSTOM_REGEX','')
        _CUSTOM_PATTERNS = [re.compile(p) for p in raw.split('||') if p.strip()]
    except Exception:
        _CUSTOM_PATTERNS = []
    try:
        _DOMAIN_ALLOW = [d.strip().lower() for d in (os.getenv('PII_DOMAIN_ALLOW','') or '').split(',') if d.strip()]
    except Exception:
        _DOMAIN_ALLOW = []
    try:
        _IP_ALLOW = [ip.strip() for ip in (os.getenv('PII_IP_ALLOW','') or '').split(',') if ip.strip()]
    except Exception:
        _IP_ALLOW = []


def scrub_text(s: str) -> str:
    if not _CUSTOM_PATTERNS and not _DOMAIN_ALLOW and not _IP_ALLOW:
        _load_policy()
    s = _EMAIL.sub('[email]', s)
    s = _PHONE.sub('[phone]', s)
    s = _CARD.sub('[card]', s)
    s = _SSN.sub('[ssn]', s)
    # Replace IP except allowed list
    if _IP.search(s):
        def _repl_ip(m):
            ip = m.group(0)
            return ip if ip in _IP_ALLOW else '[ip]'
        s = _IP.sub(_repl_ip, s)
    # Replace emails with allowed domains preserved
    if _EMAIL.search(s):
        def _repl_email(m):
            e = m.group(0)
            dom = e.split('@')[-1].lower()
            return e if dom in _DOMAIN_ALLOW else '[email]'
        s = _EMAIL.sub(_repl_email, s)
    # Custom regex
    for pat in _CUSTOM_PATTERNS:
        s = pat.sub('[redacted]', s)
    return s


def scrub_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in rec.items():
        if isinstance(v, str):
            out[k] = scrub_text(v)
        elif isinstance(v, dict):
            out[k] = scrub_record(v)
        elif isinstance(v, list):
            out[k] = [scrub_text(x) if isinstance(x, str) else x for x in v]
        else:
            out[k] = v
    return out


def classify_evidence(rec: Dict[str, Any]) -> Tuple[str, str]:
    """Return (classification, destination) based on fields present.

    classification: PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED
    destination: teams|ticket|internal_only
    """
    # Simple heuristic for stub
    contain_pii = any(isinstance(v, str) and (_EMAIL.search(v) or _SSN.search(v) or _CARD.search(v)) for v in rec.values())
    if contain_pii:
        return 'CONFIDENTIAL', 'ticket'
    return 'INTERNAL', 'teams'

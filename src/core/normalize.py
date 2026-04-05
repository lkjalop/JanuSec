"""Normalization helpers for emails/domains.

Lightweight (no external deps). Falls back gracefully when punycode/IDNA
encoding fails. Used by ingestion endpoints to canonicalize identifiers.
"""
from __future__ import annotations

import re
from typing import Optional

_EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")


def normalize_domain(domain: Optional[str]) -> Optional[str]:
    if not domain or not isinstance(domain, str):
        return domain
    d = domain.strip().lower().strip('<>')
    try:
        d = d.encode('idna').decode('ascii')
    except Exception:
        pass
    return d


def normalize_email(email: Optional[str]) -> Optional[str]:
    if not email or not isinstance(email, str):
        return email
    e = email.strip().lower().strip('<>')
    if '@' in e:
        local, _, dom = e.rpartition('@')
        dom_n = normalize_domain(dom)
        if dom_n:
            e = f"{local}@{dom_n}"
    if len(e) > 320:
        e = e[:320]
    return e

__all__ = ["normalize_domain", "normalize_email"]

from __future__ import annotations

import ipaddress
import idna
import re
from typing import Optional


def normalize_ip(v: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(v.strip()))
    except Exception:
        return None


def normalize_domain(d: str) -> str:
    d = d.strip()
    try:
        return idna.decode(d.lower())
    except Exception:
        return d.lower()


def domain_suffix(d: str) -> str:
    d = d.lower().strip()
    parts = d.split('.')
    if len(parts) < 2:
        return d
    return '.'.join(parts[-2:])


_sha256_re = re.compile(r'^[0-9a-fA-F]{64}$')
def validate_sha256(s: str) -> bool:
    return bool(_sha256_re.match(s.strip()))


def normalize_email(e: str) -> str:
    return e.strip().lower()

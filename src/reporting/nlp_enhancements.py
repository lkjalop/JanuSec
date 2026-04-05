import re
from typing import Optional, Dict, Any

# Simple regexes for normalization
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.|$)){4}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b")
USER_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}\b")


def normalize_ip(val: str) -> Optional[str]:
    if not val:
        return None
    m = IP_RE.search(val)
    return m.group(0) if m else None


def normalize_hash(val: str) -> Optional[str]:
    if not val:
        return None
    v = val.strip().lower()
    if SHA256_RE.fullmatch(v):
        return v
    if SHA1_RE.fullmatch(v):
        return v
    if MD5_RE.fullmatch(v):
        return v
    return None


def normalize_domain(val: str) -> Optional[str]:
    if not val:
        return None
    m = DOMAIN_RE.search(val)
    return m.group(0).lower() if m else None


def normalize_user(val: str) -> Optional[str]:
    if not val:
        return None
    v = val.strip()
    # simple: lowercase and strip domain part
    if '@' in v:
        v = v.split('@', 1)[0]
    return v.lower()


def canonicalize_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return a new dict with canonical fields (ip, domain, file_hash, user, host).

    This is lightweight and best-effort for prompt enrichment and correlator mapping.
    """
    out = {}
    for k, v in record.items():
        if v is None:
            continue
        s = str(v)
        ip = normalize_ip(s)
        if ip:
            out.setdefault('ip', set()).add(ip)
            continue
        hsh = normalize_hash(s)
        if hsh:
            out.setdefault('file_hash', set()).add(hsh)
            continue
        dom = normalize_domain(s)
        if dom:
            out.setdefault('domain', set()).add(dom)
            continue
        # heuristic for hostnames (contains hyphen or digits)
        if '-' in s or any(ch.isdigit() for ch in s):
            out.setdefault('host', set()).add(s.lower())
            continue
        # fallback: consider as user-like
        user = normalize_user(s)
        if user:
            out.setdefault('user', set()).add(user)
    # Convert sets to lists
    return {k: list(v) for k, v in out.items()}

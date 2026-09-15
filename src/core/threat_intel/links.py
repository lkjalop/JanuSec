"""Simple threat-intel link builders for hashes, domains and IPs.

This module returns template URLs for VirusTotal, HybridAnalysis and ANY.RUN
so the frontend and explain APIs can provide quick analyst link-outs.

No external calls or API keys are performed; this is purely link construction.
"""

from __future__ import annotations

from typing import Optional, Dict

VT_BASE = 'https://www.virustotal.com/gui'
HYBRID = 'https://www.hybrid-analysis.com/sample'
ANYRUN = 'https://app.any.run/tasks'


def vt_link_for_hash(hash_val: str) -> Optional[str]:
    if not hash_val:
        return None
    h = str(hash_val).lower()
    return f"{VT_BASE}/file/{h}/detection"


def vt_link_for_domain(domain: str) -> Optional[str]:
    if not domain:
        return None
    d = str(domain).lower()
    return f"{VT_BASE}/domain/{d}"


def vt_link_for_ip(ip: str) -> Optional[str]:
    if not ip:
        return None
    return f"{VT_BASE}/ip-address/{ip}/community"


def hybrid_for_hash(hash_val: str) -> Optional[str]:
    if not hash_val:
        return None
    return f"{HYBRID}/{hash_val}"


def anyrun_for_hash(hash_val: str) -> Optional[str]:
    if not hash_val:
        return None
    return f"{ANYRUN}/{hash_val}"


def build_links(meta: Dict[str, str]) -> Dict[str, Optional[str]]:
    """Given meta dict with possible keys 'sha256','domain','ip', return a links dict."""
    out: Dict[str, Optional[str]] = {}
    sha = meta.get('sha256') or meta.get('hash')
    domain = meta.get('domain')
    ip = meta.get('ip')
    out['vt_file'] = vt_link_for_hash(sha) if sha else None
    out['hybrid'] = hybrid_for_hash(sha) if sha else None
    out['anyrun'] = anyrun_for_hash(sha) if sha else None
    out['vt_domain'] = vt_link_for_domain(domain) if domain else None
    out['vt_ip'] = vt_link_for_ip(ip) if ip else None
    return out


__all__ = ['vt_link_for_hash', 'vt_link_for_domain', 'vt_link_for_ip', 'hybrid_for_hash', 'anyrun_for_hash', 'build_links']

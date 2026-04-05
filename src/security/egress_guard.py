from __future__ import annotations

import os
import socket
import ipaddress
from urllib.parse import urlparse


def ssrf_check(url: str) -> tuple[bool, str | None]:
    """Validate an outbound URL against SSRF safety rules.

    Rules:
    - Require scheme and netloc
    - Disallow http (unless ALLOW_INSECURE_WEBHOOK_HTTP enabled)
    - Disallow localhost/loopback/private/link-local/multicast/reserved
    - Optional allowlist via INTEGRATIONS_EGRESS_ALLOWLIST (host suffix match)
    Returns (ok, reason).
    """
    try:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return False, 'bad_url'
        if p.scheme.lower() != 'https' and os.getenv('ALLOW_INSECURE_WEBHOOK_HTTP','0').lower() not in {'1','true','yes'}:
            return False, 'insecure_scheme'
        host = (p.hostname or '').lower()
        if host in {'localhost','127.0.0.1'}:
            return False, 'loopback_host'
        # Resolve host and check all addresses
        try:
            infos = socket.getaddrinfo(host, None)
        except Exception:
            return False, 'resolve_failed'
        for _,_,_,_,addr in infos:
            ip = ipaddress.ip_address(addr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return False, 'private_or_loopback'
        allow = [h.strip() for h in (os.getenv('INTEGRATIONS_EGRESS_ALLOWLIST','') or '').split(',') if h.strip()]
        if allow:
            h = host.lstrip('.').lower()
            if not any(h == a.lstrip('.').lower() or h.endswith('.'+a.lstrip('.').lower()) for a in allow):
                return False, 'not_in_allowlist'
        return True, None
    except Exception:
        return False, 'exception'


def ssrf_ok(url: str) -> bool:
    ok, _ = ssrf_check(url)
    return ok


__all__ = ['ssrf_check','ssrf_ok']

